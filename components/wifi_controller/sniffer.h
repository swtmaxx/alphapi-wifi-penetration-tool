/**
 * @file sniffer.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides an interface for sniffer functionality.
 */
#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdbool.h>
#include "esp_event.h"

ESP_EVENT_DECLARE_BASE(SNIFFER_EVENTS);

enum {
    SNIFFER_EVENT_CAPTURED_DATA,
    SNIFFER_EVENT_CAPTURED_MGMT,
    SNIFFER_EVENT_CAPTURED_CTRL
};

/**
 * @brief Event loop that carries captured frames.
 *
 * Captured frames are posted to this private loop instead of the default one,
 * so a busy sniffer cannot starve other components. Register handlers with
 * esp_event_handler_register_with(loop, SNIFFER_EVENTS, ...).
 *
 * @return handle, or NULL before wifictl_sniffer_start() was called
 */
esp_event_loop_handle_t wifictl_sniffer_event_loop(void);

/**
 * @brief Create the sniffer event loop if it does not exist yet.
 *
 * Callers that register handlers before starting the sniffer (for example the
 * client counter) use this so the loop is ready.
 *
 * @return true when the loop is available
 */
bool wifictl_sniffer_loop_ready(void);

/**
 * @brief Sets sniffer filter for specific frame types. 
 * 
 * @param data sniff data frames
 * @param mgmt sniff management frames
 * @param ctrl sniff control frames
 */
void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl);

/**
 * @brief Post every frame to the event loop instead of only capture-relevant ones.
 *
 * Default false: the Wi-Fi callback drops ordinary data frames and unrelated
 * management frames, which keeps the 32-slot queue empty during a capture.
 * Only Beacon/Probe-Response/Action management frames and LLC 0x888e data
 * frames are posted; association, authentication and deauthentication frames
 * are dropped unless this is enabled.
 * The client counter sets this to true because it has to see all data frames.
 */
void wifictl_sniffer_set_post_filter(bool post_all);

/**
 * @brief Start promiscuous mode on given channel
 * 
 * @param channel channel on which sniffer should operate
 */
void wifictl_sniffer_start(uint8_t channel);

/**
 * @brief Stop promisuous mode
 * 
 */
void wifictl_sniffer_stop();

/**
 * @brief Whether promiscuous mode is currently running.
 *
 * While the sniffer owns the radio the channel is already set and the
 * management AP must not be reconfigured, otherwise the AP restart would
 * break the capture.
 */
bool wifictl_sniffer_is_active(void);

/**
 * @brief Number of frames dropped because the sniffer queue was full.
 *
 * Frames are dropped rather than blocking the Wi-Fi driver, so this counter is
 * the only way to notice that a capture is losing traffic.
 */
uint32_t wifictl_sniffer_dropped_frames(void);

#endif