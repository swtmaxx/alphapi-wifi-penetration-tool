/**
 * @file attack_pmkid.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides interface to control PMKID attack.
 */
#ifndef ATTACK_PMKID_H
#define ATTACK_PMKID_H

#include "attack.h"

/**
 * @brief PMKID attack variants.
 *
 * SINGLE probes the AP the operator selected; BATCH sweeps every scanned AP and
 * reports which ones hand out a PMKID. Batch does not need a client to be
 * online, so it is the highest-yield path on PMF-protected networks.
 */
typedef enum {
    ATTACK_PMKID_METHOD_SINGLE = 0,
    ATTACK_PMKID_METHOD_BATCH = 1,
} attack_pmkid_method_t;

/**
 * @brief Starts PMKID attack with given attack_config_t.
 * 
 * To stop PMKID attack, call attack_pmkid_stop().
 * 
 * @param attack_config attack configuration with valid ap_record (SINGLE) or
 *                      only a method (BATCH, which scans for its own targets)
 */
void attack_pmkid_start(attack_config_t *attack_config);

/**
 * @brief Progress of a running (or last finished) batch sweep.
 *
 * @param done  number of APs probed so far
 * @param total number of candidate APs in the sweep (0 when none ran yet)
 * @param hits  number of APs that returned a PMKID
 */
void attack_pmkid_batch_progress(unsigned *done, unsigned *total, unsigned *hits);

/** @brief True while a batch sweep is running. */
bool attack_pmkid_batch_active(void);
/**
 * @brief Stops PMKID attack.
 * 
 * It stops everything that attack_pmkid_start() started and resets values to original state.
 */
void attack_pmkid_stop();

#endif