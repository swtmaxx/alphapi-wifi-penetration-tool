/**
 * @file ap_scanner.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides an interface for AP scanning functionality.
 */
#ifndef AP_SCANNER_H
#define AP_SCANNER_H

#include <stdbool.h>
#include "esp_err.h"
#include "esp_wifi_types.h"

/**
 * @brief Linked list of wifi_ap_record_t records.
 * 
 */
typedef struct {
    uint16_t count;
    wifi_ap_record_t records[CONFIG_SCAN_MAX_AP];
} wifictl_ap_records_t;

/**
 * @brief Switches ESP into scanning mode and stores result.
 * 
 */
esp_err_t wifictl_scan_nearby_aps(void);

/**
 * @brief Copies the latest AP records into caller-owned storage.
 *
 * @return true when the snapshot was copied successfully.
 */
bool wifictl_copy_ap_records(wifictl_ap_records_t *out);

/**
 * @brief Copies the AP record at the given index into caller-owned storage.
 *
 * Returns a snapshot instead of a pointer into the scanned array, so a scan that
 * runs concurrently cannot tear the record the caller is about to attack.
 *
 * @param index index into the last scan result
 * @param out destination record
 * @return true when the index was in range
 */
bool wifictl_copy_ap_record(unsigned index, wifi_ap_record_t *out);

/**
 * @brief Creates the scanner mutex before any task can race for it.
 */
bool wifictl_ap_scanner_early_init(void);

#endif
