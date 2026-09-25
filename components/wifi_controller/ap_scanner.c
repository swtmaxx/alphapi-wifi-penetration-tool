/**
 * @file ap_scanner.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements AP scanning functionality.
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 */
#include "ap_scanner.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "wifi_controller.h"

static const char* TAG = "wifi_controller/ap_scanner";
/**
 * @brief Stores last scanned AP records into linked list.
 * 
 */
static wifictl_ap_records_t ap_records;
static SemaphoreHandle_t scanner_mutex;

static bool ensure_scanner_mutex(void)
{
    if (scanner_mutex == NULL) scanner_mutex = xSemaphoreCreateMutex();
    return scanner_mutex != NULL;
}

esp_err_t wifictl_scan_nearby_aps(void)
{
    if (!ensure_scanner_mutex()) return ESP_ERR_NO_MEM;
    if (!wifictl_radio_try_acquire()) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(scanner_mutex, 0) != pdTRUE) {
        wifictl_radio_release();
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGD(TAG, "Scanning nearby APs...");

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .show_hidden = true,
    };

    esp_err_t ret = esp_wifi_scan_start(&scan_config, true);
    if (ret == ESP_OK) {
        uint16_t count = CONFIG_SCAN_MAX_AP;
        ret = esp_wifi_scan_get_ap_records(&count, ap_records.records);
        if (ret == ESP_OK) {
            ap_records.count = count;
        }
    }
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Wi-Fi scan failed: %s", esp_err_to_name(ret));
        ap_records.count = 0;
        xSemaphoreGive(scanner_mutex);
        wifictl_radio_release();
        return ret;
    }
    ESP_LOGI(TAG, "Found %u APs.", ap_records.count);
    ESP_LOGD(TAG, "Scan done.");
    xSemaphoreGive(scanner_mutex);
    wifictl_radio_release();
    return ESP_OK;
}

const wifictl_ap_records_t *wifictl_get_ap_records() {
    return &ap_records;
}

bool wifictl_copy_ap_records(wifictl_ap_records_t *out)
{
    if (out == NULL || !ensure_scanner_mutex()) return false;
    xSemaphoreTake(scanner_mutex, portMAX_DELAY);
    memcpy(out, &ap_records, sizeof(*out));
    xSemaphoreGive(scanner_mutex);
    return true;
}

const wifi_ap_record_t *wifictl_get_ap_record(unsigned index) {
    if(index >= ap_records.count){
        ESP_LOGE(TAG, "Index out of bounds! %u records available, but %u requested", ap_records.count, index);
        return NULL;
    }
    return &ap_records.records[index];
}
