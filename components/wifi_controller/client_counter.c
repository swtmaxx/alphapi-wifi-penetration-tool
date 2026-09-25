/**
 * @file client_counter.c
 * @brief Counts online clients per AP by passive sniffing.
 *
 * See client_counter.h for the detection rationale and limitations.
 */
#include "client_counter.h"

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
#include "frame_analyzer_types.h"

static const char *TAG = "client_counter";

#define CLIENT_COUNT_MAX_AP      32
#define CLIENT_COUNT_MAX_CLIENTS 16
#define CLIENT_COUNT_DWELL_MS    2000
#define CLIENT_COUNT_MAX_CHANNEL 13

typedef struct {
    uint8_t bssid[6];
    uint8_t macs[CLIENT_COUNT_MAX_CLIENTS][6];
    uint8_t count;
} client_entry_t;

static client_entry_t entries[CLIENT_COUNT_MAX_AP];
static unsigned entry_count = 0;
static uint8_t allowed_bssids[CLIENT_COUNT_MAX_AP][6];
static unsigned allowed_count = 0;
static SemaphoreHandle_t counter_mutex = NULL;
static volatile bool counting_active = false;
static bool handler_registered = false;

static bool ensure_mutex(void)
{
    if (counter_mutex == NULL) counter_mutex = xSemaphoreCreateMutex();
    return counter_mutex != NULL;
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
    if (data == NULL || id != SNIFFER_EVENT_CAPTURED_DATA) return;

    wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)data;
    if (packet->rx_ctrl.sig_len < 24) return;

    const data_frame_t *frame = (const data_frame_t *) packet->payload;
    const frame_control_t *fc = &frame->mac_header.frame_control;
    if (fc->type != 2 || (fc->to_ds && fc->from_ds)) return;

    const uint8_t *bssid;
    const uint8_t *client;
    if (fc->to_ds) {
        bssid = frame->mac_header.addr1;
        client = frame->mac_header.addr2;
    } else if (fc->from_ds) {
        bssid = frame->mac_header.addr2;
        client = frame->mac_header.addr1;
    } else {
        return;
    }
    if ((client[0] & 0x01) || memcmp(client, bssid, 6) == 0) return;

    if (!ensure_mutex()) return;
    xSemaphoreTake(counter_mutex, portMAX_DELAY);

    int slot = -1;
    for (unsigned i = 0; i < entry_count; i++) {
        if (memcmp(entries[i].bssid, bssid, 6) == 0) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        bool allowed = false;
        for (unsigned i = 0; i < allowed_count; i++) {
            if (memcmp(allowed_bssids[i], bssid, 6) == 0) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            xSemaphoreGive(counter_mutex);
            return;
        }
        if (entry_count >= CLIENT_COUNT_MAX_AP) {
            xSemaphoreGive(counter_mutex);
            return;
        }
        slot = (int)entry_count++;
        memcpy(entries[slot].bssid, bssid, 6);
        entries[slot].count = 0;
    }

    for (unsigned i = 0; i < entries[slot].count; i++) {
        if (memcmp(entries[slot].macs[i], client, 6) == 0) {
            xSemaphoreGive(counter_mutex);
            return;
        }
    }
    if (entries[slot].count < CLIENT_COUNT_MAX_CLIENTS) {
        memcpy(entries[slot].macs[entries[slot].count], client, 6);
        entries[slot].count++;
    }
    xSemaphoreGive(counter_mutex);
}

static void unregister_client_handler(void)
{
    if (!handler_registered) return;
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop != NULL) {
        esp_err_t err = esp_event_handler_unregister_with(
            loop, SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA,
            &client_frame_handler);
        if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to unregister client handler: %s", esp_err_to_name(err));
        }
    }
    handler_registered = false;
}

static void finish_client_counting(bool restore_ap)
{
    if (wifictl_sniffer_is_active()) wifictl_sniffer_stop();
    unregister_client_handler();
    if (restore_ap) wifictl_mgmt_ap_restore();
    counting_active = false;
    wifictl_radio_release();
}

static void client_counting_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(500));
    wifictl_ap_records_t ap_records;
    if (!wifictl_copy_ap_records(&ap_records) || ap_records.count == 0) {
        ESP_LOGW(TAG, "No scanned APs; run a network scan first");
        finish_client_counting(false);
        vTaskDelete(NULL);
        return;
    }

    wifictl_clear_client_counts();
    if (!ensure_mutex()) {
        finish_client_counting(false);
        vTaskDelete(NULL);
        return;
    }
    xSemaphoreTake(counter_mutex, portMAX_DELAY);
    allowed_count = ap_records.count < CLIENT_COUNT_MAX_AP
                        ? ap_records.count : CLIENT_COUNT_MAX_AP;
    for (unsigned i = 0; i < allowed_count; i++) {
        memcpy(allowed_bssids[i], ap_records.records[i].bssid, 6);
    }
    xSemaphoreGive(counter_mutex);

    wifictl_sniffer_filter_frame_types(true, false, false);

    bool channels[CLIENT_COUNT_MAX_CHANNEL + 1] = { false };
    for (unsigned i = 0; i < ap_records.count; i++) {
        uint8_t channel = ap_records.records[i].primary;
        if (channel >= 1 && channel <= CLIENT_COUNT_MAX_CHANNEL) {
            channels[channel] = true;
        }
    }

    ESP_LOGI(TAG, "Counting clients on scanned channels");
    if (!wifictl_mgmt_ap_suspend()) {
        ESP_LOGE(TAG, "Could not suspend management AP for channel sweep");
        finish_client_counting(false);
        vTaskDelete(NULL);
        return;
    }
    for (uint8_t channel = 1; channel <= CLIENT_COUNT_MAX_CHANNEL; channel++) {
        if (!channels[channel]) continue;
        ESP_LOGD(TAG, "Sniffing channel %u", channel);
        wifictl_sniffer_start(channel);
        if (!wifictl_sniffer_is_active()) continue;
        vTaskDelay(pdMS_TO_TICKS(CLIENT_COUNT_DWELL_MS));
        wifictl_sniffer_stop();
    }

    finish_client_counting(true);
    ESP_LOGI(TAG, "Client counting finished");
    counting_active = false;
    vTaskDelete(NULL);
}

bool wifictl_start_client_counting(void)
{
    if (!ensure_mutex()) return false;
    if (counting_active) {
        ESP_LOGW(TAG, "Client counting already running");
        return false;
    }
    if (!wifictl_radio_try_acquire()) return false;

    if (!handler_registered) {
        /* The sniffer may not have run yet, so create its loop first. */
        if (!wifictl_sniffer_loop_ready()) {
            ESP_LOGE(TAG, "Sniffer loop not ready; cannot count clients");
            wifictl_radio_release();
            return false;
        }
        esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
        esp_err_t err = esp_event_handler_register_with(
            loop, SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA,
            &client_frame_handler, NULL);
        if (err != ESP_OK) {
            wifictl_radio_release();
            ESP_LOGE(TAG, "Failed to register client handler: %s", esp_err_to_name(err));
            return false;
        }
        handler_registered = true;
    }

    counting_active = true;
    if (xTaskCreate(client_counting_task, "count_clients", 4096, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to start client counting task");
        counting_active = false;
        unregister_client_handler();
        wifictl_radio_release();
        return false;
    }
    return true;
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
