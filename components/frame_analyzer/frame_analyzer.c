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
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "wifi_controller.h"
#include "frame_analyzer_parser.h"

static const char *TAG = "frame_analyzer";
static uint8_t target_bssid[6];
static search_type_t search_type = -1;


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

    if(!is_frame_bssid_matching(frame, target_bssid)){
        ESP_LOGV(TAG, "Not matching BSSIDs.");
        return;
    }

    eapol_packet_t *eapol_packet = parse_eapol_packet((data_frame_t *) frame->payload);
    if(eapol_packet == NULL){
        ESP_LOGV(TAG, "Not an EAPOL packet.");
        return;
    }

    eapol_key_packet_t *eapol_key_packet = parse_eapol_key_packet(eapol_packet);
    if(eapol_key_packet == NULL){
        ESP_LOGV(TAG, "Not an EAPOL-Key packet");
        return;
    }

    /* Downstream handlers run on the same private loop; posting with a zero
       timeout drops rather than blocking the Wi-Fi driver when it is full. */
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL) return;

    if(search_type == SEARCH_HANDSHAKE){
        esp_event_post_to(loop, FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME,
                          frame,
                          sizeof(wifi_promiscuous_pkt_t) + frame->rx_ctrl.sig_len, 0);
        return;
    }

    if(search_type == SEARCH_PMKID){
        pmkid_item_t *pmkid_items;
        if((pmkid_items = parse_pmkid(eapol_key_packet)) == NULL){
            return;
        }
        esp_event_post_to(loop, FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID,
                          &pmkid_items, sizeof(pmkid_item_t *), 0);
        return;
    }
}

void frame_analyzer_capture_start(search_type_t search_type_arg, const uint8_t *bssid){
    ESP_LOGI(TAG, "Frame analysis started...");
    search_type = search_type_arg;
    memcpy(&target_bssid, bssid, 6);

    /* Frames arrive on the sniffer's private loop, not the default loop. */
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL) {
        ESP_LOGE(TAG, "Sniffer loop not ready; frame analysis disabled");
        return;
    }
    ESP_ERROR_CHECK(esp_event_handler_register_with(loop, SNIFFER_EVENTS,
                                                    SNIFFER_EVENT_CAPTURED_DATA,
                                                    &data_frame_handler, NULL));
}

void frame_analyzer_capture_stop(){
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL) return;
    ESP_ERROR_CHECK(esp_event_handler_unregister_with(loop, SNIFFER_EVENTS,
                                                      SNIFFER_EVENT_CAPTURED_DATA,
                                                      &data_frame_handler));
}
