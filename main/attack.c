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
static attack_status_t attack_status = { .state = READY, .type = -1, .content_size = 0, .content = NULL };
/* Own copy of the target AP so a later scan cannot invalidate the pointer mid-attack. */
static wifi_ap_record_t active_ap_record;
static esp_timer_handle_t attack_timeout_handle;
static SemaphoreHandle_t attack_status_mutex;
static bool attack_radio_reserved = false;
static bool attack_stopping = false;

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
    if (state == FINISHED || state == TIMEOUT || state == ERROR) {
        ESP_LOGD(TAG, "Stopping attack timeout timer");
        if (attack_timeout_handle != NULL && esp_timer_is_active(attack_timeout_handle)) {
            esp_timer_stop(attack_timeout_handle);
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

/**
 * @brief Latched "a usable result was captured" flag.
 *
 * Cleared by attack_reset_success_latch() when a new attack is dispatched, and
 * also by a stop task that gave up, so a later signal can still try to stop.
 * Without those resets only the very first attack would ever auto-stop.
 */
static volatile bool success_latched = false;
static volatile bool stop_task_pending = false;
static volatile attack_state_t pending_terminal_state = FINISHED;

static bool stop_attack_components(uint8_t type)
{
    switch (type) {
        case ATTACK_TYPE_HANDSHAKE: return attack_handshake_stop();
        case ATTACK_TYPE_PMKID: return attack_pmkid_stop();
        case ATTACK_TYPE_DOS: return attack_dos_stop();
        default: return false;
    }
}

static bool stop_active_attack(uint32_t expected_generation, attack_state_t terminal_state)
{
    uint8_t type;
    status_lock();
    if (attack_status.state != RUNNING || attack_generation != expected_generation ||
        attack_stopping) {
        status_unlock();
        return false;
    }
    attack_stopping = true;
    type = attack_status.type;
    status_unlock();

    if (attack_timeout_handle != NULL && esp_timer_is_active(attack_timeout_handle)) {
        esp_timer_stop(attack_timeout_handle);
    }
    bool cleanup_ok = stop_attack_components(type);

    status_lock();
    if (attack_generation == expected_generation && attack_status.state == RUNNING) {
        attack_status.state = cleanup_ok ? terminal_state : ERROR;
    }
    attack_stopping = false;
    if (attack_radio_reserved) {
        attack_radio_reserved = false;
        wifictl_radio_release();
    }
    status_unlock();
    if (!cleanup_ok) ESP_LOGE(TAG, "Attack cleanup failed");
    return cleanup_ok;
}

/**
 * @brief Deferred teardown after a successful capture.
 *
 * Runs outside the sniffer event loop so unregistering handlers there is safe.
 * @param arg the attack generation that requested this stop, as a pointer value
 */
static void deferred_stop_task(void *arg)
{
    uint32_t my_generation = (uint32_t) (uintptr_t) arg;
    vTaskDelay(pdMS_TO_TICKS(200));

    status_lock();
    bool current = (attack_status.state == RUNNING) &&
                   (attack_generation == my_generation);
    attack_state_t terminal_state = pending_terminal_state;
    status_unlock();

    if (!current) {
        status_lock();
        last_bail_state = attack_status.state;
        last_bail_gen = attack_generation;
        if (attack_generation == my_generation) {
            success_latched = false;
            stop_task_pending = false;
        }
        status_unlock();
        vTaskDelete(NULL);
        return;
    }

    bool stopped = stop_active_attack(my_generation, terminal_state);
    status_lock();
    if (attack_generation == my_generation) stop_task_pending = false;
    status_unlock();
    if (stopped && terminal_state == FINISHED) {
        autostop_acted++;
        ESP_LOGI(TAG, "Capture goal reached; attack stopped");
    } else if (terminal_state == ERROR) {
        ESP_LOGE(TAG, "Attack stopped after a capture or persistence error");
    }
    vTaskDelete(NULL);
}

/**
 * @brief Re-arm the auto-stop latch. Call when a new attack is dispatched.
 */
static void attack_reset_success_latch(void)
{
    success_latched = false;
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
    status_lock();
    if (attack_status.state != RUNNING || stop_task_pending) {
        status_unlock();
        return;
    }
    stop_task_pending = true;
    pending_terminal_state = FINISHED;
    success_latched = true;
    uint32_t generation = attack_generation;
    status_unlock();

    if (xTaskCreate(deferred_stop_task, "atk_success", 4096,
                    (void *)(uintptr_t)generation, 5, NULL) != pdPASS) {
        status_lock();
        if (attack_generation == generation) {
            stop_task_pending = false;
            success_latched = false;
        }
        status_unlock();
        ESP_LOGE(TAG, "Failed to schedule success stop");
    } else {
        autostop_scheduled++;
    }
}

void attack_signal_error(void)
{
    status_lock();
    if (attack_status.state != RUNNING || stop_task_pending) {
        status_unlock();
        return;
    }
    stop_task_pending = true;
    pending_terminal_state = ERROR;
    success_latched = false;
    uint32_t generation = attack_generation;
    status_unlock();

    if (xTaskCreate(deferred_stop_task, "atk_error", 4096,
                    (void *)(uintptr_t)generation, 5, NULL) != pdPASS) {
        status_lock();
        if (attack_generation == generation) stop_task_pending = false;
        status_unlock();
        ESP_LOGE(TAG, "Failed to schedule error cleanup");
    }
}

bool attack_append_status_content(const uint8_t *buffer, unsigned size){
    if(size == 0 || buffer == NULL){
        ESP_LOGE(TAG, "Invalid arguments for appending status content");
        return false;
    }
    status_lock();
    if (size > ATTACK_STATUS_CONTENT_MAX - attack_status.content_size) {
        status_unlock();
        ESP_LOGW(TAG, "Status content limit reached (%u bytes); dropping new data",
                 ATTACK_STATUS_CONTENT_MAX);
        return false;
    }
    char *reallocated_content = realloc(attack_status.content, attack_status.content_size + size);
    if(reallocated_content == NULL){
        status_unlock();
        ESP_LOGE(TAG, "Error reallocating status content! Status content may not be complete.");
        return false;
    }
    // copy new data after current content
    memcpy(&reallocated_content[attack_status.content_size], buffer, size);
    attack_status.content = reallocated_content;
    attack_status.content_size += size;
    status_unlock();
    return true;
}

char *attack_alloc_result_content(unsigned size) {
    if (size > ATTACK_STATUS_CONTENT_MAX) {
        ESP_LOGE(TAG, "Result content exceeds %u-byte limit", ATTACK_STATUS_CONTENT_MAX);
        return NULL;
    }
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
    status_lock();
    if (attack_status.state != RUNNING) {
        status_unlock();
        return;
    }
    uint32_t generation = attack_generation;
    status_unlock();
    stop_active_attack(generation, TIMEOUT);
}

static void set_attack_request_error(uint8_t type)
{
    status_lock();
    if (attack_status.state != RUNNING && !attack_stopping) {
        free(attack_status.content);
        attack_status.content = NULL;
        attack_status.content_size = 0;
        attack_status.state = ERROR;
        attack_status.type = type;
    }
    status_unlock();
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
    if (event_data == NULL) {
        ESP_LOGE(TAG, "Attack request has no payload");
        return;
    }
    attack_request_t request = *(const attack_request_t *)event_data;
    bool valid_type = request.type >= ATTACK_TYPE_HANDSHAKE &&
                      request.type <= ATTACK_TYPE_DOS;
    bool valid_method = (request.type == ATTACK_TYPE_HANDSHAKE &&
                         request.method <= ATTACK_HANDSHAKE_METHOD_PASSIVE) ||
                        (request.type == ATTACK_TYPE_PMKID && request.method == 0) ||
                        (request.type == ATTACK_TYPE_DOS &&
                         request.method <= ATTACK_DOS_METHOD_COMBINE_ALL);
    if (!valid_type || !valid_method) {
        ESP_LOGE(TAG, "Rejected invalid attack type/method %u/%u",
                 request.type, request.method);
        set_attack_request_error(request.type);
        return;
    }

    if (!wifictl_radio_try_acquire()) {
        ESP_LOGW(TAG, "Wi-Fi radio is busy; attack request rejected");
        set_attack_request_error(request.type);
        return;
    }

    wifictl_ap_records_t records;
    if (!wifictl_copy_ap_records(&records) || request.ap_record_id >= records.count) {
        wifictl_radio_release();
        ESP_LOGE(TAG, "No AP record for id %u", request.ap_record_id);
        set_attack_request_error(request.type);
        return;
    }

    /* Snapshot the record: scanning overwrites the shared AP array. */
    memcpy(&active_ap_record, &records.records[request.ap_record_id], sizeof(active_ap_record));

    attack_config_t attack_config = {
        .type = request.type,
        .method = request.method,
        .timeout = request.timeout
    };
    attack_config.ap_record = &active_ap_record;

    status_lock();
    if (attack_status.state == RUNNING || attack_stopping) {
        status_unlock();
        wifictl_radio_release();
        ESP_LOGW(TAG, "Attack already running");
        return;
    }
    attack_radio_reserved = true;
    attack_status.type = attack_config.type;
    attack_status.state = RUNNING;
    free(attack_status.content);
    attack_status.content = NULL;
    attack_status.content_size = 0;
    stop_task_pending = false;
    pending_terminal_state = FINISHED;
    success_latched = false;
    attack_generation++;
    uint32_t generation = attack_generation;
    status_unlock();

    attack_reset_success_latch();
    if (attack_timeout_handle != NULL && esp_timer_is_active(attack_timeout_handle)) {
        esp_timer_stop(attack_timeout_handle);
    }

    ESP_LOGI(TAG, "Starting attack type %u", attack_config.type);
    bool started = false;
    switch(attack_config.type) {
        case ATTACK_TYPE_PMKID:
            started = attack_pmkid_start(&attack_config);
            break;
        case ATTACK_TYPE_HANDSHAKE:
            started = attack_handshake_start(&attack_config);
            break;
        case ATTACK_TYPE_DOS:
            started = attack_dos_start(&attack_config);
            break;
        default:
            break;
    }
    if (!started) {
        ESP_LOGE(TAG, "Attack setup failed");
        stop_active_attack(generation, ERROR);
        return;
    }
    if (attack_config.timeout > 0) {
        esp_err_t timer_err = esp_timer_start_once(
            attack_timeout_handle, (uint64_t)attack_config.timeout * 1000000ULL);
        if (timer_err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start attack timeout: %s", esp_err_to_name(timer_err));
            stop_active_attack(generation, ERROR);
        }
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
    bool cleanup_ok = true;
    for (;;) {
        status_lock();
        bool stopping = attack_stopping;
        status_unlock();
        if (!stopping) break;
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    status_lock();
    stop_required = attack_status.state == RUNNING;
    type = attack_status.type;
    attack_generation++;
    attack_stopping = stop_required;
    stop_task_pending = false;
    success_latched = false;
    status_unlock();

    if (stop_required) {
        if (attack_timeout_handle != NULL && esp_timer_is_active(attack_timeout_handle)) {
            esp_timer_stop(attack_timeout_handle);
        }
        cleanup_ok = stop_attack_components(type);
    }

    status_lock();
    free(attack_status.content);
    attack_status.content = NULL;
    attack_status.content_size = 0;
    attack_status.type = cleanup_ok ? -1 : type;
    attack_status.state = cleanup_ok ? READY : ERROR;
    if (attack_radio_reserved) {
        attack_radio_reserved = false;
        wifictl_radio_release();
    }
    attack_stopping = false;
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
