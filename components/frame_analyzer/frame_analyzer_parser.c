/**
 * @file frame_analyzer_parser.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements parsing functionality
 */
#include "frame_analyzer_parser.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "arpa/inet.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_wifi_types.h"

#include "frame_analyzer_types.h"

static const char *TAG = "frame_analyzer:parser";

ESP_EVENT_DEFINE_BASE(FRAME_ANALYZER_EVENTS);

/**
 * @brief Debug function to print raw frame to serial
 * 
 * @param frame 
 */
void print_raw_frame(const wifi_promiscuous_pkt_t *frame){
    for(unsigned i = 0; i < frame->rx_ctrl.sig_len; i++) {
        printf("%02x", frame->payload[i]);
    }
    printf("\n");
}

/**
 * @brief Debug functions to print MAC address from given buffer to serial
 * 
 * @param a mac address buffer
 */
void print_mac_address(const uint8_t *a){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
    a[0], a[1], a[2], a[3], a[4], a[5]);
    printf("\n");
}

bool is_frame_bssid_matching(wifi_promiscuous_pkt_t *frame, uint8_t *bssid) {
    /* addr3 lives at offset 16 of the 24-byte fixed header; a shorter capture
       (or a control frame) must not be read. */
    if (frame == NULL || bssid == NULL) return false;
    if (frame->rx_ctrl.sig_len < sizeof(data_frame_mac_header_t)) return false;
    data_frame_mac_header_t *mac_header = (data_frame_mac_header_t *) frame->payload;
    return memcmp(mac_header->addr3, bssid, 6) == 0;
}

eapol_packet_t *parse_eapol_packet(data_frame_t *frame, unsigned frame_len,
                                  unsigned *eapol_len) {
    if (eapol_len != NULL) *eapol_len = 0;
    if (frame == NULL || frame_len < sizeof(data_frame_mac_header_t)) {
        ESP_LOGV(TAG, "Frame too short (%u bytes) to hold a data header", frame_len);
        return NULL;
    }

    if(frame->mac_header.frame_control.protected_frame == 1) {
        ESP_LOGV(TAG, "Protected frame, skipping...");
        return NULL;
    }

    unsigned offset = sizeof(data_frame_mac_header_t);
    if(frame->mac_header.frame_control.subtype > 7) {
        ESP_LOGV(TAG, "QoS data frame");
        // Skipping QoS field (2 bytes)
        offset += 2;
    }

    /* LLC/SNAP header (6 bytes) followed by the 2-byte EtherType. */
    if (frame_len < offset + sizeof(llc_snap_header_t) + sizeof(uint16_t)) {
        ESP_LOGV(TAG, "Frame truncated before the EtherType (%u bytes)", frame_len);
        return NULL;
    }

    const uint8_t *ether_type_field =
        (const uint8_t *) frame + offset + sizeof(llc_snap_header_t);

    // Check if frame is type of EAPoL
    if(ntohs(*(const uint16_t *) ether_type_field) == ETHER_TYPE_EAPOL) {
        unsigned available = frame_len - offset - sizeof(llc_snap_header_t) -
                             sizeof(uint16_t);
        if (available < sizeof(eapol_packet_header_t)) {
            ESP_LOGV(TAG, "EAPOL header truncated (%u bytes)", available);
            return NULL;
        }
        ESP_LOGD(TAG, "EAPOL packet");
        if (eapol_len != NULL) *eapol_len = available;
        return (eapol_packet_t *) (ether_type_field + sizeof(uint16_t));
    }
    return NULL;
}

eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet,
                                          unsigned eapol_len){
    if (eapol_packet == NULL) return NULL;
    if(eapol_packet->header.packet_type != EAPOL_KEY){
        ESP_LOGD(TAG, "Not an EAPoL-Key packet.");
        return NULL;
    }
    if (eapol_len < EAPOL_KEY_DATA_OFFSET) {
        ESP_LOGD(TAG, "EAPoL-Key truncated (%u < %u bytes)",
                 eapol_len, (unsigned) EAPOL_KEY_DATA_OFFSET);
        return NULL;
    }
    return (eapol_key_packet_t *) eapol_packet->packet_body;
}

/**
 * @brief Parses all PMKIDs to linked list structure 
 * 
 * It crawlers through key data buffer and looks for PMKIDs.
 * If PMKID element is found, its saved into the list of PMKIDs.
 * @param key_data 
 * @param length of key data
 * @return pmkid_item_t* 
 */
static pmkid_item_t *parse_pmkid_from_key_data(uint8_t *key_data, const uint16_t length){
    if (key_data == NULL || length < sizeof(key_data_field_t)) return NULL;

    uint8_t *key_data_index = key_data;
    uint8_t *key_data_max_index = key_data + length;

    pmkid_item_t *pmkid_item_head = NULL;

    while (key_data_index + sizeof(key_data_field_t) <= key_data_max_index) {
        key_data_field_t *key_data_field = (key_data_field_t *) key_data_index;

        ESP_LOGV(TAG, "EAPOL-Key -> Key-Data -> type=%x; length=%x; oui=%x; data_type=%x",
                    key_data_field->type,
                    key_data_field->length,
                    key_data_field->oui,
                    key_data_field->data_type);

        /* The KDE layout is: type(1) length(1) oui+data_type(4) data(length).
           Guard against a zero/short length so the walk always advances. */
        unsigned field_len = key_data_field->length;
        if (field_len < 4 || key_data_index + 1 + field_len > key_data_max_index) {
            ESP_LOGD(TAG, "Malformed key-data field (len=%u); stop parsing", field_len);
            break;
        }

        bool matches = key_data_field->type == KEY_DATA_TYPE &&
                       ntohl(key_data_field->oui) == KEY_DATA_OUI_IEEE80211 &&
                       key_data_field->data_type == KEY_DATA_DATA_TYPE_PMKID_KDE;

        if (matches) {
            if (field_len < 4 + 16) {
                ESP_LOGD(TAG, "PMKID KDE too short (len=%u)", field_len);
            } else {
                pmkid_item_t *item = (pmkid_item_t *) calloc(1, sizeof(pmkid_item_t));
                if (item != NULL) {
                    memcpy(item->pmkid, key_data_field->data, 16);
                    item->next = pmkid_item_head;
                    pmkid_item_head = item;
                    ESP_LOGI(TAG, "Found PMKID");
                } else {
                    ESP_LOGE(TAG, "Failed to allocate PMKID item");
                }
            }
        }

        key_data_index += 1 + field_len;
    }

    return pmkid_item_head;
}

pmkid_item_t *parse_pmkid(eapol_key_packet_t *eapol_key, unsigned eapol_len){
    if (eapol_key == NULL) return NULL;
    if(eapol_key->key_data_length == 0){
        ESP_LOGD(TAG, "Empty Key Data");
        return NULL;
    }

    if(eapol_key->key_information.encrypted_key_data == 1){
        ESP_LOGD(TAG, "Key Data encrypted");
        return NULL;
    }

    /* key_data_length is attacker-controlled: it must not point past the bytes
       that were actually captured. */
    if (eapol_len < EAPOL_KEY_DATA_OFFSET) {
        ESP_LOGD(TAG, "EAPoL-Key too short for key data (%u bytes)", eapol_len);
        return NULL;
    }
    unsigned available = eapol_len - EAPOL_KEY_DATA_OFFSET;
    unsigned key_data_length = ntohs(eapol_key->key_data_length);
    if (key_data_length > available) {
        ESP_LOGD(TAG, "Key Data claims %u bytes but only %u were captured",
                 key_data_length, available);
        return NULL;
    }

    return parse_pmkid_from_key_data(eapol_key->key_data, key_data_length);
}
