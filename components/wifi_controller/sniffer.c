/**
 * @file sniffer.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements sniffer logic.
 */
#include "sniffer.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "sniffer"; 

ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);

/* Dedicated event loop for captured frames so a busy sniffer cannot fill the
   shared default loop and stall unrelated components (e.g. the attack reset
   posted from the UI task). 64 slots, 0 = drop when full. */
#define SNIFFER_LOOP_QUEUE_SIZE 64
static esp_event_loop_handle_t sniffer_loop = NULL;


static bool ensure_sniffer_loop(void)
{
    if (sniffer_loop != NULL) return true;

    esp_event_loop_args_t args = {
        .queue_size = SNIFFER_LOOP_QUEUE_SIZE,
        .task_name = "sniffer_evt",
        .task_priority = 5,
        .task_stack_size = 3584,
        .task_core_id = tskNO_AFFINITY,
    };
    esp_err_t err = esp_event_loop_create(&args, &sniffer_loop);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create sniffer event loop: %s", esp_err_to_name(err));
        sniffer_loop = NULL;
        return false;
    }
    return true;
}

esp_event_loop_handle_t wifictl_sniffer_event_loop(void)
{
    return sniffer_loop;
}

bool wifictl_sniffer_loop_ready(void)
{
    return ensure_sniffer_loop();
}

/**
 * @brief Callback for promiscuous reciever. 
 * 
 * It forwards captured frames into event pool and sorts them based on their type
 * - Data
 * - Management
 * - Control
 * 
 * @param buf 
 * @param type 
 */
static void frame_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    ESP_LOGV(TAG, "Captured frame %d.", (int) type);

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buf;

    int32_t event_id;
    switch (type) {
        case WIFI_PKT_DATA:
            event_id = SNIFFER_EVENT_CAPTURED_DATA;
            break;
        case WIFI_PKT_MGMT:
            event_id = SNIFFER_EVENT_CAPTURED_MGMT;
            break;
        case WIFI_PKT_CTRL:
            event_id = SNIFFER_EVENT_CAPTURED_CTRL;
            break;
        default:
            return;
    }

    /* Post to the sniffer's own loop: during an attack every captured frame
       lands here, and the shared default loop (32 slots) would be flooded,
       stalling any other component that posts to it. Drop frames instead of
       blocking the Wi-Fi driver when the sniffer queue is full. */
    esp_event_post_to(sniffer_loop, SNIFFER_EVENTS, event_id, frame,
                      frame->rx_ctrl.sig_len + sizeof(wifi_promiscuous_pkt_t),
                      0);
}

/**
 * @see https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_wifi.html#_CPPv425wifi_promiscuous_filter_t
 */
void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl) {
    wifi_promiscuous_filter_t filter = { .filter_mask = 0 };
    /* Independent checks: callers may request several frame types at once
       (for example data + management when counting clients). */
    if(data) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    }
    if(mgmt) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    }
    if(ctrl) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    esp_wifi_set_promiscuous_filter(&filter);
}

void wifictl_sniffer_start(uint8_t channel) {
    ESP_LOGI(TAG, "Starting promiscuous mode...");
    if (!ensure_sniffer_loop()) {
        ESP_LOGE(TAG, "Sniffer event loop unavailable; frames will be dropped");
    }
    // ESP32 cannot switch port, if there is some STA connected to AP
    ESP_LOGD(TAG, "Kicking all connected STAs from AP");
    esp_err_t err = esp_wifi_deauth_sta(0);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to deauth connected STAs: %s", esp_err_to_name(err));
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&frame_handler);
}

void wifictl_sniffer_stop() {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    esp_wifi_set_promiscuous(false);
}