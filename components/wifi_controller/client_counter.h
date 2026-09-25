/**
 * @file client_counter.h
 * @brief Counts online clients per AP by passive sniffing.
 *
 * A frame whose source MAC differs from its destination MAC comes from a
 * client; a frame where they are equal is emitted by the AP itself (beacon,
 * probe response, ...). Counting unique source MACs per destination BSSID
 * therefore approximates the number of active clients behind each AP.
 *
 * @note Promiscuous sniffing requires the management AP to be down, so the
 *       management AP is stopped while counting and restarted afterwards.
 * @note The result is an estimate limited to clients that transmitted during
 *       the observation window.
 */
#ifndef CLIENT_COUNTER_H
#define CLIENT_COUNTER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Start the background client counting task.
 *
 * Sweeps every channel that holds a scanned AP for a short dwell time and
 * records unique client MACs. Returns immediately; poll
 * wifictl_client_counting_active() to know when the sweep finished.
 */
void wifictl_start_client_counting(void);

/**
 * @brief True while a counting sweep is running.
 */
bool wifictl_client_counting_active(void);

/**
 * @brief Number of distinct clients seen for the given BSSID (0 if none).
 */
uint8_t wifictl_get_client_count(const uint8_t bssid[6]);

/**
 * @brief Clear all previously counted clients and AP entries.
 */
void wifictl_clear_client_counts(void);

#endif /* CLIENT_COUNTER_H */