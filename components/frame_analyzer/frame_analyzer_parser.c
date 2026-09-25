/**
 * @file frame_analyzer_parser.c
 * @brief Bounded 802.11, EAPOL-Key, and PMKID parsing helpers.
 */
#include "frame_analyzer_parser.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "arpa/inet.h"
#include "esp_log.h"
#include "frame_analyzer_types.h"

static const char *TAG = "frame_analyzer:parser";

bool is_frame_bssid_matching(const wifi_promiscuous_pkt_t *frame,
                             const uint8_t *bssid)
{
    if (frame == NULL || bssid == NULL || frame->rx_ctrl.sig_len < 24) return false;

    const data_frame_t *data = (const data_frame_t *) frame->payload;
    const frame_control_t *fc = &data->mac_header.frame_control;
    if (fc->type != 2 || (fc->to_ds && fc->from_ds)) return false;

    const uint8_t *frame_bssid = fc->to_ds ? data->mac_header.addr1 :
                                 fc->from_ds ? data->mac_header.addr2 :
                                               data->mac_header.addr3;
    return memcmp(frame_bssid, bssid, 6) == 0;
}

eapol_packet_t *parse_eapol_packet(data_frame_t *frame, size_t frame_len,
                                   size_t *eapol_len)
{
    const size_t mac_header_len = offsetof(data_frame_t, body);
    if (eapol_len != NULL) *eapol_len = 0;
    if (frame == NULL || frame_len < mac_header_len) return NULL;

    frame_control_t *fc = &frame->mac_header.frame_control;
    if (fc->type != 2 || fc->protected_frame) return NULL;

    size_t offset = mac_header_len;
    if (fc->to_ds && fc->from_ds) offset += 6;
    if (fc->subtype >= 8) offset += 2;
    if (fc->htc_order && fc->subtype >= 8) offset += 4;

    const size_t llc_len = sizeof(llc_snap_header_t);
    if (offset > frame_len || frame_len - offset < llc_len + 2) return NULL;

    const uint8_t *body = (const uint8_t *) frame + offset;
    if (body[0] != 0xaa || body[1] != 0xaa || body[2] != 0x03 ||
        body[3] != 0x00 || body[4] != 0x00 || body[5] != 0x00) {
        return NULL;
    }

    uint16_t ether_type;
    memcpy(&ether_type, body + llc_len, sizeof(ether_type));
    if (ntohs(ether_type) != ETHER_TYPE_EAPOL) return NULL;

    size_t remaining = frame_len - offset - llc_len - 2;
    if (remaining < sizeof(eapol_packet_header_t)) return NULL;
    eapol_packet_t *packet = (eapol_packet_t *) (body + llc_len + 2);
    size_t packet_len = sizeof(eapol_packet_header_t) +
                        ntohs(packet->header.packet_body_length);
    if (packet_len > remaining) return NULL;
    if (eapol_len != NULL) *eapol_len = packet_len;
    return packet;
}

eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet,
                                           size_t eapol_len,
                                           size_t *key_body_len)
{
    const size_t key_fixed_len = offsetof(eapol_key_packet_t, key_data);
    if (key_body_len != NULL) *key_body_len = 0;
    if (eapol_packet == NULL || eapol_len < sizeof(eapol_packet_header_t)) return NULL;
    if (eapol_packet->header.packet_type != EAPOL_KEY) return NULL;

    size_t body_len = ntohs(eapol_packet->header.packet_body_length);
    if (body_len > eapol_len - sizeof(eapol_packet_header_t) || body_len < key_fixed_len) {
        return NULL;
    }

    eapol_key_packet_t *key = (eapol_key_packet_t *) eapol_packet->packet_body;
    size_t key_data_len = ntohs(key->key_data_length);
    if (key_data_len > body_len - key_fixed_len) return NULL;
    if (key_body_len != NULL) *key_body_len = body_len;
    return key;
}

static pmkid_item_t *parse_pmkid_from_key_data(const uint8_t *key_data,
                                               size_t length)
{
    pmkid_item_t *head = NULL;
    size_t offset = 0;

    while (offset + 2 <= length) {
        const uint8_t *field = key_data + offset;
        size_t field_len = field[1];
        size_t total_len = 2 + field_len;
        if (total_len > length - offset) {
            ESP_LOGD(TAG, "Truncated key-data element; stop parsing");
            break;
        }

        if (field[0] == KEY_DATA_TYPE && field_len >= 20 &&
            field[2] == 0x00 && field[3] == 0x0f && field[4] == 0xac &&
            field[5] == KEY_DATA_DATA_TYPE_PMKID_KDE) {
            pmkid_item_t *item = calloc(1, sizeof(*item));
            if (item == NULL) {
                ESP_LOGE(TAG, "Failed to allocate PMKID item");
                break;
            }
            memcpy(item->pmkid, field + 6, sizeof(item->pmkid));
            item->next = head;
            head = item;
        }

        offset += total_len;
    }
    return head;
}

pmkid_item_t *parse_pmkid(eapol_key_packet_t *eapol_key, size_t key_body_len)
{
    const size_t key_fixed_len = offsetof(eapol_key_packet_t, key_data);
    if (eapol_key == NULL || key_body_len < key_fixed_len) return NULL;
    if (eapol_key->key_information.encrypted_key_data) return NULL;

    size_t key_data_len = ntohs(eapol_key->key_data_length);
    if (key_data_len == 0 || key_data_len > key_body_len - key_fixed_len) return NULL;
    return parse_pmkid_from_key_data(eapol_key->key_data, key_data_len);
}
