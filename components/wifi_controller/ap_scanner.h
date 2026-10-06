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
 * @brief Returns AP record on given index
 * 
 * @param index 
 * @return const wifi_ap_record_t* 
 */
const wifi_ap_record_t *wifictl_get_ap_record(unsigned index);

#endif
