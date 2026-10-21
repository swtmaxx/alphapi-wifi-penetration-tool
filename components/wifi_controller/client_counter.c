/**
 * @file client_counter.c
 * @brief Counts online clients per AP by passive sniffing.
 *
 * See client_counter.h for the detection rationale and limitations.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#include "client_counter.h"

#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "sdkconfig.h"

#include "wifi_controller.h"
#include "ap_scanner.h"
#include "sniffer.h"

/* These tables are only touched by tasks, never by DMA, so they may live in
   PSRAM when it is enabled (see README: "启用 PSRAM"). With the default build
   (CONFIG_SPIRAM off) the attribute expands to nothing. */
#if CONFIG_SPIRAM
#include "esp_attr.h"
#define LARGE_RAM_ATTR EXT_RAM_BSS_ATTR
#else
#define LARGE_RAM_ATTR
#endif

static const char *TAG = "client_counter";

/* Internal DRAM is the scarce resource here (the ESP-IDF 6.x image needs
   ~24 KB more of it than 5.0 did). 24 APs x 16 clients covers a 13-channel
   sweep and the default scan limit (CONFIG_SCAN_MAX_AP = 20); the counters are
   an estimate anyway. */
#define CLIENT_COUNT_MAX_AP      24
#define CLIENT_COUNT_MAX_CLIENTS 16
#define CLIENT_COUNT_DWELL_MS    2000
#define CLIENT_COUNT_MAX_CHANNEL 13

typedef struct {
    uint8_t bssid[6];
    uint8_t macs[CLIENT_COUNT_MAX_CLIENTS][6];
    uint8_t count;
    /* True once the table was full and a MAC had to be discarded, so the UI can
       show "16+" instead of pretending the count is exact. */
    bool saturated;
} client_entry_t;

/* The table lives on the heap: at 24 APs x 16 clients it is 2.6 KB of BSS, and
   the ESP-IDF 6.1 image already overflows the static DRAM region on this chip.
   Allocating it at boot keeps the static region small; the sweep only runs on
   demand, so paying for it lazily is also the right trade. */
static client_entry_t *entries = NULL;
static unsigned entry_count = 0;
/* BSSIDs we are counting for, filled at the start of every sweep. */
static uint8_t (*tracked_bssids)[6] = NULL;
static unsigned tracked_bssid_count = 0;
static SemaphoreHandle_t counter_mutex = NULL;
static volatile bool counting_active = false;
static bool handler_registered = false;

static bool ensure_mutex(void)
{
    if (counter_mutex == NULL) counter_mutex = xSemaphoreCreateMutex();
    if (counter_mutex == NULL) return false;

    if (entries == NULL) {
        entries = calloc(CLIENT_COUNT_MAX_AP, sizeof(*entries));
    }
    if (tracked_bssids == NULL) {
        tracked_bssids = calloc(CLIENT_COUNT_MAX_AP, sizeof(*tracked_bssids));
    }
    if (entries == NULL || tracked_bssids == NULL) {
        ESP_LOGE(TAG, "Failed to allocate the client tables");
        return false;
    }
    return true;
}

bool wifictl_client_counter_early_init(void)
{
    return ensure_mutex();
}

void wifictl_clear_client_counts(void)
{
    if (!ensure_mutex()) return;
    xSemaphoreTake(counter_mutex, portMAX_DELAY);
    entry_count = 0;
    xSemaphoreGive(counter_mutex);
}

/**
 * @brief Sniffer event callback: record unique source MACs per destination BSSID.
 *
 * 802.11 fixed header layout: frame_ctrl(0-1) duration(2-3) addr1/dst(4-9)
 * addr2/src(10-15) addr3(16-21).
 */
static void client_frame_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (data == NULL) return;

    wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)data;
    if (packet->rx_ctrl.sig_len < 22) return;

    const uint8_t *frame = packet->payload;
    const uint8_t *dst = &frame[4];
    const uint8_t *src = &frame[10];

    /* Frames the AP emits itself (beacon, probe response, ...) have
       dst == src and must not be counted as clients. */
    if (memcmp(dst, src, 6) == 0) return;
    if (src[0] & 0x01) return; /* skip group/multicast sources */

    if (!ensure_mutex()) return;
    xSemaphoreTake(counter_mutex, portMAX_DELAY);

    /* Only count frames addressed to an AP we actually scanned. Beacons go to the
       broadcast address and probe responses / AP-to-STA data go to the client, so
       without this filter the AP's own transmissions were recorded as "clients"
       and pushed the real APs out of the fixed-size table. */
    bool known_ap = (tracked_bssid_count == 0);
    for (unsigned i = 0; !known_ap && i < tracked_bssid_count; i++) {
        if (memcmp(tracked_bssids[i], dst, 6) == 0) known_ap = true;
    }
    if (!known_ap) {
        xSemaphoreGive(counter_mutex);
        return;
    }

    int slot = -1;
    for (unsigned i = 0; i < entry_count; i++) {
        if (memcmp(entries[i].bssid, dst, 6) == 0) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        if (entry_count >= CLIENT_COUNT_MAX_AP) {
            xSemaphoreGive(counter_mutex);
            return;
        }
        slot = (int)entry_count++;
        memcpy(entries[slot].bssid, dst, 6);
        entries[slot].count = 0;
        entries[slot].saturated = false;
    }

    for (unsigned i = 0; i < entries[slot].count; i++) {
        if (memcmp(entries[slot].macs[i], src, 6) == 0) {
            xSemaphoreGive(counter_mutex);
            return;
        }
    }
    if (entries[slot].count < CLIENT_COUNT_MAX_CLIENTS) {
        memcpy(entries[slot].macs[entries[slot].count], src, 6);
        entries[slot].count++;
    } else {
        entries[slot].saturated = true;
    }
    xSemaphoreGive(counter_mutex);
}

static void unregister_handler(void)
{
    if (!handler_registered) return;
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop != NULL) {
        esp_event_handler_unregister_with(loop, SNIFFER_EVENTS, ESP_EVENT_ANY_ID,
                                          &client_frame_handler);
    }
    handler_registered = false;
}

static void client_counting_task(void *arg)
{
    wifictl_ap_records_t ap_records;
    if (!wifictl_copy_ap_records(&ap_records) || ap_records.count == 0) {
        ESP_LOGW(TAG, "No scanned APs; run a network scan first");
        /* Do not leave the sniffer handler registered: it would keep walking the
           table on every captured frame for no reason. */
        wifictl_sniffer_set_post_filter(false);
        unregister_handler();
        counting_active = false;
        vTaskDelete(NULL);
        return;
    }

    wifictl_clear_client_counts();

    /* Counting needs every data frame, not just EAPOL: the callback filter must
       be relaxed for the duration of the sweep. */
    wifictl_sniffer_set_post_filter(true);

    /* Remember the BSSIDs to count for; the sniffer handler filters on them. */
    if (ensure_mutex()) {
        xSemaphoreTake(counter_mutex, portMAX_DELAY);
        tracked_bssid_count = 0;
        for (unsigned i = 0; i < ap_records.count &&
                             tracked_bssid_count < CLIENT_COUNT_MAX_AP; i++) {
            memcpy(tracked_bssids[tracked_bssid_count++],
                   ap_records.records[i].bssid, 6);
        }
        xSemaphoreGive(counter_mutex);
    }

    wifictl_sniffer_filter_frame_types(true, true, false);

    bool channels[CLIENT_COUNT_MAX_CHANNEL + 1] = { false };
    for (unsigned i = 0; i < ap_records.count; i++) {
        uint8_t channel = ap_records.records[i].primary;
        if (channel >= 1 && channel <= CLIENT_COUNT_MAX_CHANNEL) {
            channels[channel] = true;
        }
    }

    ESP_LOGI(TAG, "Counting clients on scanned channels");
    for (uint8_t channel = 1; channel <= CLIENT_COUNT_MAX_CHANNEL; channel++) {
        if (!channels[channel]) continue;
        ESP_LOGD(TAG, "Sniffing channel %u", channel);
        wifictl_sniffer_start(channel);
        vTaskDelay(pdMS_TO_TICKS(CLIENT_COUNT_DWELL_MS));
        wifictl_sniffer_stop();
    }

    if (handler_registered) {
        unregister_handler();
    }
    wifictl_sniffer_set_post_filter(false);

    /* Restore the management AP on its configured channel. */
    wifictl_set_channel(CONFIG_MGMT_AP_CHANNEL);
    wifictl_mgmt_ap_start();

    ESP_LOGI(TAG, "Client counting finished");
    counting_active = false;
    vTaskDelete(NULL);
}

void wifictl_start_client_counting(void)
{
    if (!ensure_mutex()) return;
    if (counting_active) {
        ESP_LOGW(TAG, "Client counting already running");
        return;
    }

    if (!handler_registered) {
        /* The sniffer may not have run yet, so create its loop first. */
        if (!wifictl_sniffer_loop_ready()) {
            ESP_LOGE(TAG, "Sniffer loop not ready; cannot count clients");
            counting_active = false;
            return;
        }
        esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
        esp_event_handler_register_with(loop, SNIFFER_EVENTS, ESP_EVENT_ANY_ID,
                                        &client_frame_handler, NULL);
        handler_registered = true;
    }

    counting_active = true;
    if (xTaskCreate(client_counting_task, "count_clients", 4096, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to start client counting task");
        counting_active = false;
    }
}

bool wifictl_client_counting_active(void)
{
    return counting_active;
}

uint8_t wifictl_get_client_count(const uint8_t bssid[6])
{
    if (!ensure_mutex()) return 0;
    uint8_t result = 0;
    xSemaphoreTake(counter_mutex, portMAX_DELAY);
    for (unsigned i = 0; i < entry_count; i++) {
        if (memcmp(entries[i].bssid, bssid, 6) == 0) {
            result = entries[i].count;
            break;
        }
    }
    xSemaphoreGive(counter_mutex);
    return result;
}

bool wifictl_client_count_saturated(const uint8_t bssid[6])
{
    if (!ensure_mutex()) return false;
    bool saturated = false;
    xSemaphoreTake(counter_mutex, portMAX_DELAY);
    for (unsigned i = 0; i < entry_count; i++) {
        if (memcmp(entries[i].bssid, bssid, 6) == 0) {
            saturated = entries[i].saturated;
            break;
        }
    }
    xSemaphoreGive(counter_mutex);
    return saturated;
}

/**
 * @brief Copy the client MACs observed for one BSSID.
 *
 * Used by the deauthentication path to aim at a specific station instead of
 * broadcasting to everyone (most clients discard group-addressed deauth).
 *
 * @return number of MACs copied
 */
unsigned wifictl_copy_client_macs(const uint8_t bssid[6], uint8_t (*out)[6], unsigned max)
{
    if (out == NULL || max == 0 || !ensure_mutex()) return 0;

    unsigned copied = 0;
    xSemaphoreTake(counter_mutex, portMAX_DELAY);
    for (unsigned i = 0; i < entry_count && copied < max; i++) {
        if (memcmp(entries[i].bssid, bssid, 6) != 0) continue;
        unsigned n = entries[i].count < max - copied ? entries[i].count : max - copied;
        for (unsigned j = 0; j < n; j++) {
            memcpy(out[copied++], entries[i].macs[j], 6);
        }
        break;
    }
    xSemaphoreGive(counter_mutex);
    return copied;
}