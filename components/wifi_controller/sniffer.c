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
   posted from the UI task). 0 = drop when full.
 *
 * esp_event copies every event onto the heap, so the queue depth bounds the peak
 * heap usage: ~1.6 KB per frame, i.e. ~50 KB here. Deeper queues risk OOM when
 * the consumer is blocked on a SPIFFS write; the drop counter below makes the
 * trade-off visible. */
#define SNIFFER_LOOP_QUEUE_SIZE 32
static esp_event_loop_handle_t sniffer_loop = NULL;


static volatile bool sniffer_active = false;
static volatile uint32_t sniffer_dropped = 0;
/* When false (the default) the Wi-Fi callback drops every frame that cannot
 * possibly matter for a capture: ordinary data frames and unrelated management
 * frames. Only the client counter turns this off, because it needs to see all
 * data frames to identify clients. */
static volatile bool sniffer_post_all = false;

void wifictl_sniffer_set_post_filter(bool post_all)
{
    sniffer_post_all = post_all;
}

uint32_t wifictl_sniffer_dropped_frames(void)
{
    return sniffer_dropped;
}

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
 * @brief Whether a frame can be useful for capture, decided in the Wi-Fi callback.
 *
 * Posting every data frame to the event loop used to fill the 32-slot queue on
 * any busy network (video streaming alone is ~99% of the frames), so the EAPOL
 * frames we actually need were dropped before frame_analyzer ever saw them.
 * Filtering here keeps the queue almost empty during a capture.
 */
static bool frame_is_interesting(const uint8_t *payload, uint16_t len, wifi_promiscuous_pkt_type_t type)
{
    if (payload == NULL || len < 24) return false;

    uint8_t fc0 = payload[0];
    uint8_t fc1 = payload[1];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    if (type == WIFI_PKT_MGMT || ftype == 0) {
        /* beacon(8) / probe response(5) / action(13) carry the SSID, RSN and
           CSA information; assoc/auth frames are not needed for capture. */
        return subtype == 8 || subtype == 5 || subtype == 13;
    }

    if (type == WIFI_PKT_DATA || ftype == 2) {
        unsigned offset = 24;
        if ((fc1 & 0x03) == 3) offset += 6;              /* 4-address */
        if (subtype & 0x08) offset += 2;                 /* QoS control */
        if ((fc1 & 0x80) && (subtype & 0x08)) offset += 4; /* HT control */
        if (len < offset + 8) return false;
        const uint8_t *llc = payload + offset;
        /* LLC/SNAP + EAPOL ethertype 0x888e */
        return llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
               llc[6] == 0x88 && llc[7] == 0x8E;
    }

    return false;   /* control frames never matter */
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

    /* Without a loop there is nowhere to deliver frames; never post to NULL. */
    if (sniffer_loop == NULL) return;

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buf;

    if (!sniffer_post_all &&
        !frame_is_interesting(frame->payload, frame->rx_ctrl.sig_len, type)) {
        return;
    }

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

    /* Drop frames instead of blocking the Wi-Fi driver when the sniffer queue is
       full, but keep a counter so the loss is at least visible on screen/logs. */
    esp_err_t err = esp_event_post_to(sniffer_loop, SNIFFER_EVENTS, event_id, frame,
                                      frame->rx_ctrl.sig_len + sizeof(wifi_promiscuous_pkt_t),
                                      0);
    if (err != ESP_OK) sniffer_dropped++;
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
        /* Without a loop every frame would be dropped: do not pretend to capture. */
        ESP_LOGE(TAG, "Sniffer event loop unavailable; not starting promiscuous mode");
        return;
    }
    if (channel == 0 || channel > 13) {
        ESP_LOGE(TAG, "Channel out of range for the sniffer: %u", channel);
        return;
    }
    // ESP32 cannot switch port, if there is some STA connected to AP
    ESP_LOGD(TAG, "Kicking all connected STAs from AP");
    esp_err_t err = esp_wifi_deauth_sta(0);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to deauth connected STAs: %s", esp_err_to_name(err));
    }
    err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        /* Staying on the wrong channel would silently capture nothing. */
        ESP_LOGE(TAG, "Failed to set channel %u: %s", channel, esp_err_to_name(err));
        return;
    }
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&frame_handler);
    sniffer_active = true;
}

bool wifictl_sniffer_is_active(void)
{
    return sniffer_active;
}

void wifictl_sniffer_stop() {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    esp_wifi_set_promiscuous(false);
    sniffer_active = false;
}