/**
 * @file ap_security.h
 * @brief Parses the security-relevant information elements of a Beacon frame.
 *
 * Knowing whether an AP requires 802.11w (PMF) explains why a deauthentication
 * attack does nothing: PMF-enabled stations discard forged management frames.
 * The information lives in the RSN element of the Beacon, which the capture
 * path already receives, so no extra radio time is needed.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#ifndef AP_SECURITY_H
#define AP_SECURITY_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    AP_PMF_UNKNOWN = 0,   /**< not parsed yet */
    AP_PMF_NONE,          /**< AP does not advertise PMF at all */
    AP_PMF_CAPABLE,       /**< AP supports PMF; whether it is used depends on the client */
    AP_PMF_REQUIRED,      /**< AP refuses associations without PMF (WPA3, or MFPR set) */
} ap_pmf_t;

typedef struct {
    ap_pmf_t pmf;
    bool bip_cipher;      /**< group management cipher present: PMF really enabled */
    bool wps;             /**< WPS vendor element present */
} ap_security_t;

/**
 * @brief Parse a Beacon or Probe Response frame.
 *
 * @param frame complete 802.11 frame (starting at the frame control field)
 * @param len   captured length
 * @param out   parsed result; untouched fields keep their previous value
 * @return true when the frame contained an RSN element
 */
bool wifictl_parse_ap_security(const uint8_t *frame, unsigned len, ap_security_t *out);

/**
 * @brief Last parsed result, updated by the capture path.
 *
 * The screen and the web UI read this to show "PMF required" next to a target.
 */
const ap_security_t *wifictl_last_ap_security(void);

/** @brief Store a parsed result for the UI (called by the capture path). */
void wifictl_set_last_ap_security(const ap_security_t *security);

/** @brief Human readable PMF state, for logs and the UI. */
const char *wifictl_pmf_name(ap_pmf_t pmf);

#endif /* AP_SECURITY_H */
