#include "wifi_controller.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char* TAG = "wifi_controller";
/**
 * @brief Stores current state of Wi-Fi interface
 */
static bool wifi_init = false;
static uint8_t original_mac_ap[6];
static SemaphoreHandle_t radio_reservation = NULL;

static wifi_auth_mode_t management_auth_mode(void)
{
#if CONFIG_MGMT_AP_AUTH_ON
    return WIFI_AUTH_WPA2_PSK;
#else
    return WIFI_AUTH_OPEN;
#endif
}

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data){

}

/**
 * @brief Initializes Wi-Fi interface into APSTA mode and starts it.
 * 
 * @attention This function should be called only once.
 */
static void wifi_init_apsta(){
    if (radio_reservation == NULL) {
        radio_reservation = xSemaphoreCreateBinary();
        if (radio_reservation == NULL) abort();
        xSemaphoreGive(radio_reservation);
    }
    ESP_ERROR_CHECK(esp_netif_init());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    // save original AP MAC address
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));

    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_init = true;
}

bool wifictl_ap_start(wifi_config_t *wifi_config) {
    if (wifi_config == NULL) return false;
    ESP_LOGD(TAG, "Starting AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    esp_err_t err = esp_wifi_set_config(ESP_IF_WIFI_AP, wifi_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure AP: %s", esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "AP configured with SSID length %u", wifi_config->ap.ssid_len);
    return true;
}

bool wifictl_mgmt_ap_start(void){
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
#if CONFIG_MGMT_AP_AUTH_ON
            .password = CONFIG_MGMT_AP_PASSWORD,
#else
            .password = "",
#endif
            .channel = CONFIG_MGMT_AP_CHANNEL,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = management_auth_mode()
        },
    };
    if (!wifictl_ap_start(&mgmt_wifi_config)) return false;
    wifictl_move_mgmt_ap_to_channel(CONFIG_MGMT_AP_CHANNEL);
    return true;
}

bool wifictl_mgmt_ap_suspend(void)
{
    if (!wifi_init) return false;
    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to suspend management AP: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

bool wifictl_mgmt_ap_restore(void)
{
    if (!wifi_init) return false;
    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to restore APSTA mode: %s", esp_err_to_name(err));
        return false;
    }
    bool mac_ok = wifictl_restore_ap_mac();
    return wifictl_mgmt_ap_start() && mac_ok;
}

bool wifictl_radio_try_acquire(void)
{
    if (radio_reservation == NULL) return false;
    return xSemaphoreTake(radio_reservation, 0) == pdTRUE;
}

void wifictl_radio_release(void)
{
    if (radio_reservation != NULL) xSemaphoreGive(radio_reservation);
}

bool wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]){
    if (ap_record == NULL) return false;
    ESP_LOGD(TAG, "Connecting STA to AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false
        },
    };
    memcpy(sta_wifi_config.sta.ssid, ap_record->ssid,
           sizeof(sta_wifi_config.sta.ssid));

    if(password != NULL){
        if(strlen(password) >= 64) {
            ESP_LOGE(TAG, "Password is too long. Max supported length is 64");
            return false;
        }
        memcpy(sta_wifi_config.sta.password, password, strlen(password) + 1);
    }

    ESP_LOGD(TAG, "Connecting to target AP on channel %u", ap_record->primary);

    esp_err_t err = esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_wifi_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure STA: %s", esp_err_to_name(err));
        return false;
    }
    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start STA connection: %s", esp_err_to_name(err));
        return false;
    }
    return true;

}

void wifictl_sta_disconnect(){
    esp_err_t ret = esp_wifi_disconnect();
    if (ret != ESP_OK && ret != ESP_ERR_WIFI_NOT_CONNECT) {
        ESP_LOGW(TAG, "Failed to disconnect STA: %s", esp_err_to_name(ret));
    }
}

bool wifictl_set_ap_mac(const uint8_t *mac_ap){
    if (mac_ap == NULL) return false;
    ESP_LOGD(TAG, "Changing AP MAC address...");
    esp_err_t err = esp_wifi_set_mac(WIFI_IF_AP, mac_ap);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to change AP MAC: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

void wifictl_get_ap_mac(uint8_t *mac_ap){
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

bool wifictl_restore_ap_mac(void){
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    esp_err_t err = esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to restore AP MAC: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

void wifictl_get_sta_mac(uint8_t *mac_sta){
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_move_mgmt_ap_to_channel(uint8_t channel){
    if((channel == 0) || (channel > 13)){
        ESP_LOGE(TAG, "Channel out of range for management AP: %u", channel);
        return;
    }

    /* Reconfiguring the AP is what actually moves the radio: in APSTA mode a
       plain esp_wifi_set_channel() is undone by the running management AP. */
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
#if CONFIG_MGMT_AP_AUTH_ON
            .password = CONFIG_MGMT_AP_PASSWORD,
#else
            .password = "",
#endif
            .channel = channel,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = management_auth_mode()
        },
    };
    esp_err_t ret = esp_wifi_set_config(ESP_IF_WIFI_AP, &mgmt_wifi_config);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to move management AP to channel %u: %s",
                 channel, esp_err_to_name(ret));
        return;
    }

    /* Keep the interface call as well so a non-AP STA path still lands here. */
    wifictl_set_channel(channel);
    ESP_LOGI(TAG, "Management AP moved to channel %u", channel);
}

void wifictl_set_channel(uint8_t channel){
    if((channel == 0) || (channel >  13)){
        ESP_LOGE(TAG,"Channel out of range. Expected value from <1,13> but got %u", channel);
        return;
    }
    esp_err_t ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set Wi-Fi channel %u: %s", channel, esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "Wi-Fi channel set to %u", channel);
    }
}
