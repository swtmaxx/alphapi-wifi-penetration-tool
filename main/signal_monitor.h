/**
 * @file signal_monitor.h
 * @brief Wi-Fi signal probing: a sorted list of nearby APs and a live RSSI
 *        tracker for one locked target.
 *
 * Two modes with very different costs:
 *
 *  - List mode periodically runs a full scan (all channels), which takes the
 *    radio away from the management AP for a moment, so the web UI can stall.
 *  - Target mode does not scan at all: it parks the radio on the target channel
 *    and reads the RSSI of every Beacon the AP sends (about 10 Hz), so the web
 *    UI keeps working and the reading is genuinely live.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#ifndef SIGNAL_MONITOR_H
#define SIGNAL_MONITOR_H

#include <stdbool.h>
#include <stdint.h>

#define SIGNAL_LIST_MAX 12

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
} signal_ap_t;

typedef struct {
    signal_ap_t aps[SIGNAL_LIST_MAX];
    unsigned count;
    bool scanning;
    bool target_locked;
    char target_ssid[33];
    int8_t target_rssi;     /**< smoothed (EMA) value */
    int8_t target_peak;     /**< strongest reading since the lock */
    int8_t target_trough;   /**< weakest reading since the lock */
    uint32_t target_samples;
    uint8_t target_channel;
    uint32_t target_idle_ms;   /**< ms since the last Beacon of the target */
    uint32_t list_age_ms;      /**< ms since the last completed scan */
} signal_snapshot_t;

/** @brief Create the internal lock. Call once from app_main. */
bool signal_monitor_init(void);

/** @brief Start the periodic scan task (stops target mode first). */
void signal_monitor_start_list(void);

/** @brief Stop the periodic scan task. */
void signal_monitor_stop_list(void);

/**
 * @brief Lock onto one AP and start live Beacon RSSI tracking.
 *
 * Leaves list mode, moves the management AP to the target channel and starts
 * promiscuous reception of that channel's Beacons.
 */
bool signal_monitor_lock_target(const uint8_t *bssid, uint8_t channel, const char *ssid);

/** @brief Stop live tracking and return the management AP to its channel. */
void signal_monitor_unlock_target(void);

/** @brief Reset peak/trough/average of the locked target. */
void signal_monitor_reset_target_stats(void);

/** @brief Copy the current state. */
void signal_monitor_get(signal_snapshot_t *out);

/** @brief True while a target is locked. */
bool signal_monitor_target_locked(void);

/**
 * @brief Periodic housekeeping: re-tune a target that went silent.
 *
 * An AP can change channel (DFS, night mode) or the operator can walk out of
 * range. After 5 s without a Beacon this rescans for the target BSSID and locks
 * onto its new channel, at most once every 10 s.
 */
void signal_monitor_poll(void);

/**
 * @brief Rescan and re-lock the current target on whatever channel it uses now.
 *
 * Releases the radio, scans, and locks again when the BSSID is found.
 */
bool signal_monitor_retune_target(void);

#endif /* SIGNAL_MONITOR_H */
