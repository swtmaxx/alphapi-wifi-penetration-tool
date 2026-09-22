/**
 * @file attack.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-02
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements common attack wrapper.
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 */

#include "attack.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"

#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_dos.h"
#include "webserver.h"
#include "wifi_controller.h"

static const char* TAG = "attack";
static attack_status_t attack_status = { .state = READY, .type = -1, .content_size = 0, .content = NULL };
static esp_timer_handle_t attack_timeout_handle;
static SemaphoreHandle_t attack_status_mutex;

static void status_lock(void)
{
    if (attack_status_mutex != NULL) {
        xSemaphoreTake(attack_status_mutex, portMAX_DELAY);
    }
}

static void status_unlock(void)
{
    if (attack_status_mutex != NULL) {
        xSemaphoreGive(attack_status_mutex);
    }
}

const attack_status_t *attack_get_status() {
    return &attack_status;
}

bool attack_get_status_snapshot(attack_status_t *snapshot)
{
    if (snapshot == NULL) return false;

    memset(snapshot, 0, sizeof(*snapshot));
    status_lock();
    snapshot->state = attack_status.state;
    snapshot->type = attack_status.type;
    snapshot->content_size = attack_status.content_size;
    if (attack_status.content != NULL && attack_status.content_size > 0) {
        snapshot->content = malloc(attack_status.content_size);
        if (snapshot->content == NULL) {
            status_unlock();
            return false;
        }
        memcpy(snapshot->content, attack_status.content, attack_status.content_size);
    }
    status_unlock();
    return true;
}

void attack_free_status_snapshot(attack_status_t *snapshot)
{
    if (snapshot == NULL) return;
    free(snapshot->content);
    snapshot->content = NULL;
    snapshot->content_size = 0;
}

void attack_update_status(attack_state_t state) {
    status_lock();
    attack_status.state = state;
    status_unlock();
    if(state == FINISHED) {
        ESP_LOGD(TAG, "Stopping attack timeout timer");
        if (esp_timer_is_active(attack_timeout_handle)) {
            ESP_ERROR_CHECK(esp_timer_stop(attack_timeout_handle));
        }
    } 
}

void attack_append_status_content(uint8_t *buffer, unsigned size){
    if(size == 0){
        ESP_LOGE(TAG, "Size can't be 0 if you want to reallocate");
        return;
    }
    status_lock();
    char *reallocated_content = realloc(attack_status.content, attack_status.content_size + size);
    if(reallocated_content == NULL){
        status_unlock();
        ESP_LOGE(TAG, "Error reallocating status content! Status content may not be complete.");
        return;
    }
    // copy new data after current content
    memcpy(&reallocated_content[attack_status.content_size], buffer, size);
    attack_status.content = reallocated_content;
    attack_status.content_size += size;
    status_unlock();
}

char *attack_alloc_result_content(unsigned size) {
    status_lock();
    free(attack_status.content);
    attack_status.content = NULL;
    attack_status.content_size = size;
    attack_status.content = (char *) malloc(size);
    char *content = attack_status.content;
    status_unlock();
    return content;
}

/**
 * @brief Callback function for attack timeout timer.
 * 
 * This function is called when attack times out. 
 * It updates attack status state to TIMEOUT.
 * It calls appropriate abort functions based on current attack type.
 * @param arg not used.
 */
static void attack_timeout(void* arg){
    ESP_LOGD(TAG, "Attack timed out");

    uint8_t type;
    status_lock();
    if (attack_status.state != RUNNING) {
        status_unlock();
        return;
    }
    attack_status.state = TIMEOUT;
    type = attack_status.type;
    status_unlock();

    switch(type) {
        case ATTACK_TYPE_PMKID:
            ESP_LOGI(TAG, "Aborting PMKID attack...");
            attack_pmkid_stop();
            break;
        case ATTACK_TYPE_HANDSHAKE:
            ESP_LOGI(TAG, "Abort HANDSHAKE attack...");
            attack_handshake_stop();
            break;
        case ATTACK_TYPE_PASSIVE:
            ESP_LOGI(TAG, "Abort PASSIVE attack...");
            break;
        case ATTACK_TYPE_DOS:
            ESP_LOGI(TAG, "Abort DOS attack...");
            attack_dos_stop();
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack type. Not aborting anything");
    }
}

/**
 * @brief Callback for WEBSERVER_EVENT_ATTACK_REQUEST event.
 * 
 * This function handles WEBSERVER_EVENT_ATTACK_REQUEST event from event loop.
 * It parses attack_request_t structure and set initial values to attack_status.
 * It sets attack state to RUNNING.
 * It starts attack timeout timer.
 * It starts attack based on chosen type.
 * 
 * @param args not used
 * @param event_base expects WEBSERVER_EVENTS
 * @param event_id expects WEBSERVER_EVENT_ATTACK_REQUEST
 * @param event_data expects attack_request_t
 */
static void attack_request_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGI(TAG, "Starting attack...");
    attack_request_t *attack_request = (attack_request_t *) event_data;
    attack_config_t attack_config = { .type = attack_request->type, .method = attack_request->method, .timeout = attack_request->timeout };
    attack_config.ap_record = wifictl_get_ap_record(attack_request->ap_record_id);

    if(attack_config.ap_record == NULL){
        ESP_LOGE(TAG, "NPE: No attack_config.ap_record!");
        return;
    }

    status_lock();
    if (attack_status.state == RUNNING) {
        status_unlock();
        ESP_LOGW(TAG, "Attack already running");
        return;
    }
    attack_status.state = RUNNING;
    attack_status.type = attack_config.type;
    status_unlock();

    // set timeout
    if (esp_timer_is_active(attack_timeout_handle)) {
        ESP_ERROR_CHECK(esp_timer_stop(attack_timeout_handle));
    }
    if (attack_config.timeout > 0) {
        ESP_ERROR_CHECK(esp_timer_start_once(attack_timeout_handle, attack_config.timeout * 1000000));
    }
    // start attack based on it's type
    switch(attack_config.type) {
        case ATTACK_TYPE_PMKID:
            attack_pmkid_start(&attack_config);
            break;
        case ATTACK_TYPE_HANDSHAKE:
            attack_handshake_start(&attack_config);
            break;
        case ATTACK_TYPE_PASSIVE:
            ESP_LOGW(TAG, "ATTACK_TYPE_PASSIVE not implemented yet!");
            break;
        case ATTACK_TYPE_DOS:
            attack_dos_start(&attack_config);
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack type!");
    }
}

/**
 * @brief Callback for WEBSERVER_EVENT_ATTACK_RESET event.
 * 
 * This callback resets attack status by freeing previously allocated status content and putting attack to READY state.
 * 
 * @param args not used
 * @param event_base expects WEBSERVER_EVENTS
 * @param event_id expects WEBSERVER_EVENT_ATTACK_RESET
 * @param event_data not used
 */
static void attack_reset_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Resetting attack status...");

    uint8_t type;
    bool stop_required;
    status_lock();
    stop_required = attack_status.state == RUNNING;
    type = attack_status.type;
    if (stop_required) attack_status.state = READY;
    status_unlock();

    if (stop_required) {
        if (esp_timer_is_active(attack_timeout_handle)) {
            ESP_ERROR_CHECK(esp_timer_stop(attack_timeout_handle));
        }
        switch (type) {
            case ATTACK_TYPE_PMKID:    attack_pmkid_stop(); break;
            case ATTACK_TYPE_HANDSHAKE: attack_handshake_stop(); break;
            case ATTACK_TYPE_DOS:      attack_dos_stop(); break;
            default: break;
        }
    }

    status_lock();
    free(attack_status.content);
    attack_status.content = NULL;
    attack_status.content_size = 0;
    attack_status.type = -1;
    attack_status.state = READY;
    status_unlock();
}

/**
 * @brief Initialises common attack resources.
 * 
 * Creates attack timeout timer.
 * Registers event loop event handlers.
 */
void attack_init(){
    attack_status_mutex = xSemaphoreCreateMutex();
    if (attack_status_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create attack status mutex");
        abort();
    }

    const esp_timer_create_args_t attack_timeout_args = {
        .callback = &attack_timeout
    };
    ESP_ERROR_CHECK(esp_timer_create(&attack_timeout_args, &attack_timeout_handle));

    ESP_ERROR_CHECK(esp_event_handler_register(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST, &attack_request_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, &attack_reset_handler, NULL));
}
