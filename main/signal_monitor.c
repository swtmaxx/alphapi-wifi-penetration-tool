/**
 * @file signal_monitor.c
 * @brief Wi-Fi signal probing implementation.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#include "signal_monitor.h"

#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#define LOG_LOCAL_LEVEL ESP_LOG_INFO
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wifi_types.h"
#include "sdkconfig.h"

#include "wifi_controller.h"

static const char *TAG = "signal_monitor";

#define LIST_REFRESH_MS   2500
#define LIST_TASK_STACK   4096
#define LIST_TASK_PRIO    3
/* EMA weight: new = (old * 3 + sample) / 4, about 0.4 s of history at 10 Hz. */
#define EMA_OLD_WEIGHT    3

static signal_snapshot_t snapshot;
static SemaphoreHandle_t snapshot_mutex = NULL;
static volatile bool list_running = false;
static TaskHandle_t list_task_handle = NULL;
static volatile bool target_locked = false;
static uint8_t target_bssid[6];
/* Timestamps (us) for the "signal lost" and "list age" indicators. */
static volatile int64_t last_sample_us = 0;
static volatile int64_t last_scan_us = 0;
static bool handler_registered = false;

static void lock_state(void)
{
    if (snapshot_mutex != NULL) xSemaphoreTake(snapshot_mutex, portMAX_DELAY);
}

static void unlock_state(void)
{
    if (snapshot_mutex != NULL) xSemaphoreGive(snapshot_mutex);
}

bool signal_monitor_init(void)
{
    if (snapshot_mutex != NULL) return true;
    snapshot_mutex = xSemaphoreCreateMutex();
    if (snapshot_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create the signal state mutex");
        return false;
    }
    memset(&snapshot, 0, sizeof(snapshot));
    return true;
}

void signal_monitor_get(signal_snapshot_t *out)
{
    if (out == NULL) return;
    int64_t now = esp_timer_get_time();

    lock_state();
    *out = snapshot;
    int64_t sample = last_sample_us;
    int64_t scan = last_scan_us;
    unlock_state();

    out->target_idle_ms = (sample > 0 && now > sample)
                          ? (uint32_t) ((now - sample) / 1000) : 0;
    out->list_age_ms = (scan > 0 && now > scan)
                       ? (uint32_t) ((now - scan) / 1000) : 0;
}

bool signal_monitor_target_locked(void)
{
    return target_locked;
}

/* ------------------------------------------------------------------ */
/* Target mode: live RSSI from Beacons                                 */
/* ------------------------------------------------------------------ */

static void target_frame_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void) arg;
    (void) base;
    (void) id;
    if (data == NULL || !target_locked) return;

    wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *) data;
    const uint8_t *frame = packet->payload;
    if (packet->rx_ctrl.sig_len < 24) return;

    /* Beacon: management frame, subtype 8. */
    if ((frame[0] & 0xFC) != 0x80) return;
    /* addr3 is the BSSID for Beacons. */
    if (memcmp(&frame[16], target_bssid, 6) != 0) return;

    int8_t rssi = packet->rx_ctrl.rssi;
    lock_state();
    if (snapshot.target_samples == 0) {
        snapshot.target_rssi = rssi;
        snapshot.target_peak = rssi;
        snapshot.target_trough = rssi;
    } else {
        snapshot.target_rssi = (int8_t) ((snapshot.target_rssi * EMA_OLD_WEIGHT + rssi) /
                                         (EMA_OLD_WEIGHT + 1));
        if (rssi > snapshot.target_peak) snapshot.target_peak = rssi;
        if (rssi < snapshot.target_trough) snapshot.target_trough = rssi;
    }
    snapshot.target_samples++;
    unlock_state();
    last_sample_us = esp_timer_get_time();
}

static void unregister_target_handler(void)
{
    if (!handler_registered) return;
    esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
    if (loop != NULL) {
        esp_event_handler_unregister_with(loop, SNIFFER_EVENTS, ESP_EVENT_ANY_ID,
                                          &target_frame_handler);
    }
    handler_registered = false;
}

bool signal_monitor_lock_target(const uint8_t *bssid, uint8_t channel, const char *ssid)
{
    if (bssid == NULL || channel == 0 || channel > 13) return false;
    if (!signal_monitor_init()) return false;

    signal_monitor_stop_list();

    /* The list task may be inside wifictl_scan_nearby_aps() right now; taking
       the radio while it scans would make the first readings useless. Cap the
       wait at 1.5 s: this runs on the UI task, and a longer freeze is worse than
       starting the probe a little early. */
    for (unsigned waited = 0; waited < 1500; waited += 50) {
        lock_state();
        bool scanning = snapshot.scanning;
        unlock_state();
        if (!scanning) break;
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    memcpy(target_bssid, bssid, 6);

    lock_state();
    memset(&snapshot.target_ssid, 0, sizeof(snapshot.target_ssid));
    if (ssid != NULL) {
        strncpy(snapshot.target_ssid, ssid, sizeof(snapshot.target_ssid) - 1);
    }
    snapshot.target_locked = true;
    snapshot.target_channel = channel;
    snapshot.target_rssi = -128;
    snapshot.target_peak = -128;
    snapshot.target_trough = 0;
    snapshot.target_samples = 0;
    unlock_state();

    target_locked = true;
    last_sample_us = esp_timer_get_time();

    /* The management AP owns the radio channel in APSTA mode, so it has to be
       moved instead of calling esp_wifi_set_channel() alone. */
    wifictl_move_mgmt_ap_to_channel(channel);
    wifictl_sniffer_filter_frame_types(false, true, false);

    if (!wifictl_sniffer_loop_ready()) {
        ESP_LOGE(TAG, "Sniffer loop unavailable");
        signal_monitor_unlock_target();
        return false;
    }
    if (!handler_registered) {
        esp_event_loop_handle_t loop = wifictl_sniffer_event_loop();
        if (esp_event_handler_register_with(loop, SNIFFER_EVENTS, ESP_EVENT_ANY_ID,
                                            &target_frame_handler, NULL) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register the signal handler");
            signal_monitor_unlock_target();
            return false;
        }
        handler_registered = true;
    }
    wifictl_sniffer_start(channel);
    ESP_LOGI(TAG, "Locked on %02X:%02X:%02X:%02X:%02X:%02X ch%d",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], channel);
    return true;
}

void signal_monitor_unlock_target(void)
{
    if (!target_locked && !handler_registered) return;

    target_locked = false;
    unregister_target_handler();
    wifictl_sniffer_stop();

    lock_state();
    snapshot.target_locked = false;
    unlock_state();

    /* Put the radio back where the management AP expects it. */
    wifictl_move_mgmt_ap_to_channel(CONFIG_MGMT_AP_CHANNEL);
    wifictl_mgmt_ap_start();
    ESP_LOGI(TAG, "Target unlocked");
}

void signal_monitor_reset_target_stats(void)
{
    lock_state();
    snapshot.target_rssi = -128;
    snapshot.target_peak = -128;
    snapshot.target_trough = 0;
    snapshot.target_samples = 0;
    unlock_state();
}

bool signal_monitor_retune_target(void)
{
    if (!target_locked) return false;

    uint8_t bssid[6];
    char ssid[sizeof(snapshot.target_ssid)];
    lock_state();
    memcpy(bssid, target_bssid, 6);
    memcpy(ssid, snapshot.target_ssid, sizeof(ssid));
    unlock_state();

    /* The radio has to be released before scanning. */
    signal_monitor_unlock_target();

    if (wifictl_scan_nearby_aps() != ESP_OK) {
        ESP_LOGW(TAG, "Retune scan failed");
        return false;
    }

    wifictl_ap_records_t records;
    if (!wifictl_copy_ap_records(&records)) return false;

    for (unsigned i = 0; i < records.count; i++) {
        if (memcmp(records.records[i].bssid, bssid, 6) != 0) continue;
        ESP_LOGI(TAG, "Target moved to channel %u", records.records[i].primary);
        return signal_monitor_lock_target(bssid, records.records[i].primary, ssid);
    }

    ESP_LOGW(TAG, "Target BSSID not found after it went silent");
    return false;
}

void signal_monitor_poll(void)
{
    if (!target_locked) return;

    int64_t now = esp_timer_get_time();
    int64_t sample = last_sample_us;
    if (sample == 0) return;
    if (now - sample < 5000 * 1000LL) return;

    static int64_t last_retune_us = 0;
    if (now - last_retune_us < 10000000LL) return;
    last_retune_us = now;

    ESP_LOGW(TAG, "Target silent for %lld ms; rescanning", (now - sample) / 1000);
    signal_monitor_retune_target();
}

/* ------------------------------------------------------------------ */
/* List mode: periodic full scan                                       */
/* ------------------------------------------------------------------ */

static int compare_rssi_desc(const void *a, const void *b)
{
    int8_t ra = ((const signal_ap_t *) a)->rssi;
    int8_t rb = ((const signal_ap_t *) b)->rssi;
    if (ra == rb) return 0;
    return ra > rb ? -1 : 1;
}

static void list_task(void *arg)
{
    (void) arg;

    while (list_running) {
        lock_state();
        snapshot.scanning = true;
        unlock_state();

        esp_err_t err = wifictl_scan_nearby_aps();
        wifictl_ap_records_t records;
        signal_ap_t found[SIGNAL_LIST_MAX];
        unsigned count = 0;

        if (err == ESP_OK && wifictl_copy_ap_records(&records)) {
            for (unsigned i = 0; i < records.count && count < SIGNAL_LIST_MAX; i++) {
                const wifi_ap_record_t *rec = &records.records[i];
                memcpy(found[count].bssid, rec->bssid, 6);
                memcpy(found[count].ssid, rec->ssid, sizeof(found[count].ssid));
                found[count].ssid[sizeof(found[count].ssid) - 1] = '\0';
                found[count].rssi = rec->rssi;
                found[count].channel = rec->primary;
                count++;
            }
        }

        /* Strongest first: that is the order the operator wants to see. */
        if (count > 1) {
            qsort(found, count, sizeof(found[0]), compare_rssi_desc);
        }

        lock_state();
        memcpy(snapshot.aps, found, count * sizeof(found[0]));
        snapshot.count = count;
        snapshot.scanning = false;
        unlock_state();
        last_scan_us = esp_timer_get_time();

        for (unsigned waited = 0; waited < LIST_REFRESH_MS && list_running; waited += 100) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    lock_state();
    snapshot.scanning = false;
    unlock_state();
    list_task_handle = NULL;
    vTaskDelete(NULL);
}

void signal_monitor_start_list(void)
{
    /* A previous task may still be unwinding (it can sit in a scan for up to a
       couple of seconds); starting another one would leave two scanners racing
       for the radio. */
    if (list_running || list_task_handle != NULL) return;
    if (!signal_monitor_init()) return;
    if (target_locked) signal_monitor_unlock_target();

    list_running = true;
    if (xTaskCreate(list_task, "sig_list", LIST_TASK_STACK, NULL, LIST_TASK_PRIO,
                    &list_task_handle) != pdPASS) {
        list_running = false;
        list_task_handle = NULL;
        ESP_LOGE(TAG, "Failed to start the scan task");
    }
}

void signal_monitor_stop_list(void)
{
    list_running = false;
}
