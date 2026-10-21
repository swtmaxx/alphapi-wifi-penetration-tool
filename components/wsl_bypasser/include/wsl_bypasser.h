/**
 * @file wsl_bypasser.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides interface for Wi-Fi Stack Libraries bypasser
 * 
 * This component bypasses blocking mechanism that doesn't allow sending some arbitrary 802.11 frames like deauth etc.
 */
#ifndef WSL_BYPASSER_H
#define WSL_BYPASSER_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_wifi_types.h"

/**
 * @brief Sends frame in frame_buffer using esp_wifi_80211_tx but bypasses blocking mechanism
 * 
 * @param frame_buffer 
 * @param size size of frame buffer
 */
void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size);

/**
 * @brief Report how many raw frames the driver accepted or rejected.
 *
 * Useful on-device diagnostics: if fail keeps growing the frames never left
 * the radio, so a deauth "doing nothing" is a transmit problem, not a target
 * problem.
 */
void wsl_bypasser_get_tx_stats(uint32_t *ok, uint32_t *fail, esp_err_t *last_err);

/**
 * @brief Sends deauthentication frame with forged source AP from given ap_record
 *  
 * This will send deauthentication frame acting as frame from given AP, and destination will be broadcast
 * MAC address - \c ff:ff:ff:ff:ff:ff
 * 
 * @param ap_record AP record with valid AP information 
 */
void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record);

/**
 * @brief Sends a deauth/disassoc frame addressed to one station.
 *
 * @param bssid    target AP (spoofed source and BSSID)
 * @param sta      destination station MAC, NULL for broadcast
 * @param reason   reason code, 7 = class 3 frame from nonassociated STA
 * @param disassoc true sends disassociation (0xA0) instead of deauth (0xC0)
 */
void wsl_bypasser_send_deauth_to(const uint8_t *bssid, const uint8_t *sta,
                                 uint8_t reason, bool disassoc);

/**
 * @brief Sends a broadcast deauth/disassoc with an explicit reason code.
 */
void wsl_bypasser_send_deauth_broadcast(const uint8_t *bssid, uint8_t reason,
                                        bool disassoc);

/**
 * @brief Sends a Null Data frame with MoreData set to wake sleeping stations.
 *
 * Without this the deauth path has no station MAC to aim at on a quiet AP.
 */
void wsl_bypasser_send_null_wake(const uint8_t *bssid);

#endif