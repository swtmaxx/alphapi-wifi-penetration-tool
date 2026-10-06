/**
 * @file attack.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-02
 * @copyright Copyright (c) 2021
 *
 * @brief Provides interface to attack wrapper
 * 
 * This file provide interface to control attack wrapper like setting current attack state, 
 * update attack status content, etc...
 */

#ifndef ATTACK_H
#define ATTACK_H

#include <stdbool.h>
#include "esp_wifi_types.h"

/**
 * @brief Implemented attack types that can be chosen.
 * 
 */
typedef enum {
    ATTACK_TYPE_PASSIVE,
    ATTACK_TYPE_HANDSHAKE,
    ATTACK_TYPE_PMKID,
    ATTACK_TYPE_DOS
} attack_type_t;

/**
 * @brief States of single attack run. 
 * 
 * @note TIMEOUT will be removed in #64
 */
typedef enum {
    READY,      ///< no attack is in progress and results from previous attack run are available.
    RUNNING,    ///< attack is in progress, attack_status_t.content may not be consistent.
    FINISHED,   ///< last attack finsihed and results are available.
    TIMEOUT,    ///< last attack timed out. This option will be moved as sub category of FINISHED state.
    STORAGE_ERROR ///< capture storage failed or ran out of space.
} attack_state_t;

/**
 * @brief Attack config parsed from webserver request
 * 
 * @deprecated will be removed in #45
 */
typedef struct {
    uint8_t type;
    uint8_t method;
    uint8_t timeout;
    const wifi_ap_record_t *ap_record;
} attack_config_t;

/**
 * @brief Contains current attack status.
 * 
 * This structure contains all information and data about latest attack.
 */
typedef struct {
    uint8_t state;  ///< attack_state_t
    uint8_t type;   ///< attack_type_t
    uint16_t content_size;
    char *content;
} attack_status_t;

/**
 * @brief Copy the current attack status and result content.
 *
 * Returns a consistent copy; the content belongs to the snapshot and must be
 * released with attack_free_status_snapshot().
 *
 * @param snapshot caller-owned destination
 * @return true when the snapshot was taken
 */
bool attack_get_status_snapshot(attack_status_t *snapshot);

/**
 * @brief Release content allocated by attack_get_status_snapshot().
 */
void attack_free_status_snapshot(attack_status_t *snapshot);

/**
 * @brief Function to update current status of attack.
 * 
 * If FINISHED state is passed, then the attack timeout timer is stopped.
 * @param state new attack state of type attack_state_t to be set
 */
void attack_update_status(attack_state_t state);

/**
 * @brief Report that the attack reached its goal and should stop now.
 *
 * Safe to call from an event handler: the actual teardown runs on a short
 * deferred task so the caller's event loop is not unregistered from inside
 * its own dispatch.
 */
void attack_signal_success(void);

/**
 * @brief Report a capture-storage failure from a sniffer event handler.
 *
 * Teardown is deferred so event handlers can be unregistered safely outside
 * the sniffer event loop.
 */
void attack_signal_storage_error(const char *message);

/**
 * @brief Initialises attack wrapper. This function should be callend only once.
 * 
 * This function creates all necessary resources for attack wrapper. It has to be called before any attack can be run.
 */
void attack_init();

/**
 * @brief Allocates status content of given size.
 *  
 * @param size size to be allocated
 * @return char* pointer to newly allocated status content
 */
char *attack_alloc_result_content(unsigned size);

/**
 * @brief Reallocates current status content and appends new data.
 * 
 * @param buffer new data to be appended to status content
 * @param size size of the new data to be appended
 */
void attack_append_status_content(uint8_t *buffer, unsigned size);

/**
 * @brief Snapshot of the auto-stop state machine, for on-device diagnosis.
 *
 * @param generation current attack generation
 * @param latched    whether attack_signal_success() has already fired
 * @param stop_tasks number of stop tasks scheduled
 * @param stopped    number of stop tasks that actually tore down the attack
 * @param rearmed    number of re-arm operations at dispatch time
 * @param bail_state state seen by the last stop task that gave up (-1 if none)
 * @param bail_gen   generation seen by the last stop task that gave up
 */
void attack_get_autostop_debug(uint32_t *generation, bool *latched,
                               uint32_t *stop_tasks, uint32_t *stopped,
                               uint32_t *rearmed, int *bail_state,
                               uint32_t *bail_gen);

#endif
