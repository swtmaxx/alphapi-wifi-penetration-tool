/**
 * @file frame_analyzer.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements frame analysis
 */
#include "frame_analyzer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "wifi_controller.h"
#include "frame_analyzer_parser.h"

static const char *TAG = "frame_analyzer";
ESP_EVENT_DEFINE_BASE(FRAME_ANALYZER_EVENTS);
static uint8_t target_bssid[6];
static search_type_t search_type = -1;
static bool data_handler_registered = false;


/**
 * @brief Analyzes data frames from sniffer.
 *  
 * @param args 
 * @param event_base 
 * @param event_id 
 * @param event_data 
 */
static void data_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGV(TAG, "Handling DATA frame");
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;

    if (!is_frame_bssid_matching(frame, target_bssid)) {
        ESP_LOGV(TAG, "Not matching BSSIDs.");
        return;
    }

    size_t eapol_len = 0;
    eapol_packet_t *eapol_packet = parse_eapol_packet(
        (data_frame_t *) frame->payload, frame->rx_ctrl.sig_len, &eapol_len);
    if (eapol_packet == NULL) {
        ESP_LOGV(TAG, "Not an EAPOL packet.");
        return;
    }

    size_t key_body_len = 0;
    eapol_key_packet_t *eapol_key_packet = parse_eapol_key_packet(
        eapol_packet, eapol_len, &key_body_len);
    if (eapol_key_packet == NULL) {
        ESP_LOGV(TAG, "Not an EAPOL-Key packet");
        return;
    }

    /* Downstream handlers run on the same private loop; posting with a zero
       timeout drops rather than blocking the Wi-Fi driver when it is full. */
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL) return;

    if(search_type == SEARCH_HANDSHAKE){
        esp_err_t err = esp_event_post_to(loop, FRAME_ANALYZER_EVENTS,
                                          DATA_FRAME_EVENT_EAPOLKEY_FRAME, frame,
                                          sizeof(wifi_promiscuous_pkt_t) +
                                              frame->rx_ctrl.sig_len, 0);
        if (err != ESP_OK) ESP_LOGV(TAG, "Dropping EAPOL event: %s", esp_err_to_name(err));
        return;
    }

    if(search_type == SEARCH_PMKID){
        pmkid_item_t *pmkid_items;
        if ((pmkid_items = parse_pmkid(eapol_key_packet, key_body_len)) == NULL) {
            return;
        }
        pmkid_capture_t capture = { .items = pmkid_items };
        frame_control_t *fc = &((data_frame_t *) frame->payload)->mac_header.frame_control;
        if (fc->from_ds && !fc->to_ds) {
            memcpy(capture.ap_mac,
                   ((data_frame_t *) frame->payload)->mac_header.addr2, 6);
            memcpy(capture.sta_mac,
                   ((data_frame_t *) frame->payload)->mac_header.addr1, 6);
        } else if (fc->to_ds && !fc->from_ds) {
            memcpy(capture.ap_mac,
                   ((data_frame_t *) frame->payload)->mac_header.addr1, 6);
            memcpy(capture.sta_mac,
                   ((data_frame_t *) frame->payload)->mac_header.addr2, 6);
        } else {
            memcpy(capture.ap_mac,
                   ((data_frame_t *) frame->payload)->mac_header.addr3, 6);
            memcpy(capture.sta_mac,
                   ((data_frame_t *) frame->payload)->mac_header.addr2, 6);
        }
        esp_err_t err = esp_event_post_to(loop, FRAME_ANALYZER_EVENTS,
                                          DATA_FRAME_EVENT_PMKID, &capture,
                                          sizeof(capture), 0);
        if (err != ESP_OK) {
            while (pmkid_items != NULL) {
                pmkid_item_t *next = pmkid_items->next;
                free(pmkid_items);
                pmkid_items = next;
            }
        }
        return;
    }
}

bool frame_analyzer_capture_start(search_type_t search_type_arg, const uint8_t *bssid){
    if (bssid == NULL || !wifictl_sniffer_loop_ready()) return false;
    ESP_LOGI(TAG, "Frame analysis started...");
    search_type = search_type_arg;
    memcpy(&target_bssid, bssid, 6);

    /* Frames arrive on the sniffer's private loop, not the default loop. */
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL) {
        ESP_LOGE(TAG, "Sniffer loop not ready; frame analysis disabled");
        return false;
    }
    if (data_handler_registered) {
        esp_event_handler_unregister_with(loop, SNIFFER_EVENTS,
                                          SNIFFER_EVENT_CAPTURED_DATA,
                                          &data_frame_handler);
        data_handler_registered = false;
    }
    esp_err_t err = esp_event_handler_register_with(loop, SNIFFER_EVENTS,
                                                    SNIFFER_EVENT_CAPTURED_DATA,
                                                    &data_frame_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register data handler: %s", esp_err_to_name(err));
        return false;
    }
    data_handler_registered = true;
    return true;
}

void frame_analyzer_capture_stop(){
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL || !data_handler_registered) return;
    esp_err_t err = esp_event_handler_unregister_with(loop, SNIFFER_EVENTS,
                                                      SNIFFER_EVENT_CAPTURED_DATA,
                                                      &data_frame_handler);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGW(TAG, "Failed to unregister data handler: %s", esp_err_to_name(err));
    }
    data_handler_registered = false;
}
