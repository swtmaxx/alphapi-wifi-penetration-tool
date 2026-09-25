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
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
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
/* Upper bound for status result content to keep RAM use predictable. */
#define ATTACK_STATUS_CONTENT_MAX (64 * 1024)
static attack_status_t attack_status = { .state = READY, .type = -1, .content_size = 0, .content = NULL };
/* Own copy of the target AP so a later scan cannot invalidate the pointer mid-attack. */
static wifi_ap_record_t active_ap_record;
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
    if(state == FINISHED || state == STORAGE_ERROR) {
        ESP_LOGD(TAG, "Stopping attack timeout timer");
        if (esp_timer_is_active(attack_timeout_handle)) {
            ESP_ERROR_CHECK(esp_timer_stop(attack_timeout_handle));
        }
    } 
}

/**
 * @brief Generation counter, bumped for every dispatched attack.
 *
 * A deferred stop task may outlive the attack that spawned it (the user can
 * abort and restart within the delay window). Comparing generations makes the
 * task act only on the attack it belongs to, so it can never tear down a
 * run that started afterwards.
 */
static volatile uint32_t attack_generation = 0;

/* Auto-stop accounting, surfaced through attack_get_autostop_debug(). */
static volatile uint32_t autostop_scheduled = 0;
static volatile uint32_t autostop_acted = 0;
static volatile uint32_t autostop_rearmed = 0;
/* Why the most recent stop task bailed out, for on-device diagnosis. */
static volatile int last_bail_state = -1;
static volatile uint32_t last_bail_gen = 0;
static volatile bool storage_error_latched = false;
static char storage_error_message[96] = "抓包文件保存失败";

/**
 * @brief Latched "a usable result was captured" flag.
 *
 * Cleared by attack_reset_success_latch() when a new attack is dispatched, and
 * also by a stop task that gave up, so a later signal can still try to stop.
 * Without those resets only the very first attack would ever auto-stop.
 */
static volatile bool success_latched = false;

/**
 * @brief Deferred teardown after a successful capture.
 *
 * Runs outside the sniffer event loop so unregistering handlers there is safe.
 * @param arg the attack generation that requested this stop, as a pointer value
 */
static void success_stop_task(void *arg)
{
    uint32_t my_generation = (uint32_t) (uintptr_t) arg;
    vTaskDelay(pdMS_TO_TICKS(200));

    uint8_t type;
    status_lock();
    bool current = (attack_status.state == RUNNING) &&
                   (attack_generation == my_generation);
    type = attack_status.type;
    status_unlock();

    if (!current) {
        /* Either already finished, or a newer attack owns the state now.
           Release the latch so a later signal can still try to stop. */
        last_bail_state = attack_status.state;
        last_bail_gen = attack_generation;
        success_latched = false;
        vTaskDelete(NULL);
        return;
    }

    autostop_acted++;
    attack_update_status(FINISHED);
    if (esp_timer_is_active(attack_timeout_handle)) {
        esp_timer_stop(attack_timeout_handle);
    }

    switch (type) {
        case ATTACK_TYPE_HANDSHAKE: attack_handshake_stop(); break;
        case ATTACK_TYPE_PMKID:     attack_pmkid_stop(); break;
        default: break;
    }

    ESP_LOGI(TAG, "Goal reached; attack stopped");
    vTaskDelete(NULL);
}

static void storage_error_stop_task(void *arg)
{
    uint32_t my_generation = (uint32_t) (uintptr_t) arg;
    vTaskDelay(pdMS_TO_TICKS(200));

    uint8_t type;
    status_lock();
    bool current = (attack_status.state == RUNNING) &&
                   (attack_generation == my_generation);
    type = attack_status.type;
    status_unlock();

    if (!current) {
        storage_error_latched = false;
        vTaskDelete(NULL);
        return;
    }

    attack_update_status(STORAGE_ERROR);
    char *message = attack_alloc_result_content(strlen(storage_error_message) + 1);
    if (message != NULL) strcpy(message, storage_error_message);

    switch (type) {
        case ATTACK_TYPE_HANDSHAKE: attack_handshake_stop(); break;
        case ATTACK_TYPE_PMKID:     attack_pmkid_stop(); break;
        default: break;
    }

    ESP_LOGE(TAG, "Capture storage error: %s", storage_error_message);
    vTaskDelete(NULL);
}

/**
 * @brief Re-arm the auto-stop latch. Call when a new attack is dispatched.
 */
static void attack_reset_success_latch(void)
{
    success_latched = false;
    storage_error_latched = false;
    storage_error_message[0] = '\0';
    autostop_rearmed++;
}

/**
 * @brief Snapshot of the auto-stop state machine, for on-device diagnosis.
 *
 * The AlphaPi has no readable CDC console, so these counters are the only way
 * to tell why a run did or did not stop by itself.
 *
 * @param generation  current attack generation
 * @param latched     whether attack_signal_success() has already fired
 * @param stop_tasks  number of stop tasks that were scheduled
 * @param stopped     number of stop tasks that actually tore the attack down
 * @param rearmed     number of times the latch was reset at dispatch time
 */
void attack_get_autostop_debug(uint32_t *generation, bool *latched,
                               uint32_t *stop_tasks, uint32_t *stopped,
                               uint32_t *rearmed, int *bail_state,
                               uint32_t *bail_gen)
{
    if (generation) *generation = attack_generation;
    if (latched) *latched = success_latched;
    if (stop_tasks) *stop_tasks = autostop_scheduled;
    if (stopped) *stopped = autostop_acted;
    if (rearmed) *rearmed = autostop_rearmed;
    if (bail_state) *bail_state = last_bail_state;
    if (bail_gen) *bail_gen = last_bail_gen;
}

void attack_signal_success(void)
{
    if (success_latched) return;
    success_latched = true;
    /* 4096 bytes is enough for the teardown path. */
    void *generation = (void *) (uintptr_t) attack_generation;
    if (xTaskCreate(success_stop_task, "atk_success", 4096, generation, 5, NULL) != pdPASS) {
        success_latched = false;
        ESP_LOGE(TAG, "Failed to schedule success stop");
    } else {
        autostop_scheduled++;
    }
}

void attack_signal_storage_error(const char *message)
{
    if (storage_error_latched) return;
    storage_error_latched = true;
    if (message != NULL && message[0] != '\0') {
        strncpy(storage_error_message, message, sizeof(storage_error_message) - 1);
        storage_error_message[sizeof(storage_error_message) - 1] = '\0';
    } else {
        strcpy(storage_error_message, "抓包文件保存失败");
    }

    void *generation = (void *) (uintptr_t) attack_generation;
    if (xTaskCreate(storage_error_stop_task, "capture_error", 4096,
                    generation, 5, NULL) != pdPASS) {
        storage_error_latched = false;
        ESP_LOGE(TAG, "Failed to schedule storage-error stop");
    }
}

void attack_append_status_content(uint8_t *buffer, unsigned size){
    if(size == 0 || buffer == NULL){
        ESP_LOGE(TAG, "Invalid arguments for appending status content");
        return;
    }
    status_lock();
    if (attack_status.content_size + size > ATTACK_STATUS_CONTENT_MAX) {
        status_unlock();
        ESP_LOGW(TAG, "Status content limit reached (%u bytes); dropping new data",
                 ATTACK_STATUS_CONTENT_MAX);
        return;
    }
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
    attack_status.content_size = 0;

    char *content = NULL;
    if (size > 0) {
        content = (char *) malloc(size);
        if (content == NULL) {
            ESP_LOGE(TAG, "Failed to allocate %u bytes for result content", size);
        } else {
            attack_status.content = content;
            attack_status.content_size = size;
        }
    }
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
    const wifi_ap_record_t *selected = wifictl_get_ap_record(attack_request->ap_record_id);
    if(selected == NULL){
        ESP_LOGE(TAG, "No AP record for id %u", attack_request->ap_record_id);
        return;
    }

    /* Snapshot the record: scanning overwrites the shared AP array. */
    memcpy(&active_ap_record, selected, sizeof(active_ap_record));

    attack_config_t attack_config = { .type = attack_request->type, .method = attack_request->method, .timeout = attack_request->timeout };
    attack_config.ap_record = &active_ap_record;

    status_lock();
    if (attack_status.state == RUNNING) {
        status_unlock();
        ESP_LOGW(TAG, "Attack already running");
        return;
    }
    attack_status.state = RUNNING;
    attack_status.type = attack_config.type;
    status_unlock();

    /* Re-arm auto-stop: the previous run may have latched it. */
    attack_reset_success_latch();
    attack_generation++;

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

    /* A manual stop must not leave the auto-stop latch set. */
    attack_reset_success_latch();

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
