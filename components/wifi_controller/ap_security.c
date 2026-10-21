/**
 * @file ap_security.c
 * @brief Beacon information-element parser for PMF and WPS detection.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#include "ap_security.h"

#include <string.h>

#include "esp_log.h"

static const char *TAG = "ap_security";

/* Element IDs */
#define IE_SSID        0x00
#define IE_RSN         0x30
#define IE_VENDOR      0xDD

/* RSN capabilities bits */
#define RSN_CAP_MFPR   (1u << 6)
#define RSN_CAP_MFPC   (1u << 7)

/* WPS vendor element: 00:50:F2 type 4 */
static const uint8_t WPS_OUI[4] = { 0x00, 0x50, 0xF2, 0x04 };

static ap_security_t last_security = { .pmf = AP_PMF_UNKNOWN };

const ap_security_t *wifictl_last_ap_security(void)
{
    return &last_security;
}

void wifictl_set_last_ap_security(const ap_security_t *security)
{
    if (security == NULL) return;
    last_security = *security;
}

const char *wifictl_pmf_name(ap_pmf_t pmf)
{
    switch (pmf) {
        case AP_PMF_NONE:     return "none";
        case AP_PMF_CAPABLE:  return "capable";
        case AP_PMF_REQUIRED: return "required";
        default:              return "unknown";
    }
}

/**
 * @brief Parse the RSN element body.
 *
 * Layout (802.11-2016 9.4.2.24): version(2), group cipher(4),
 * pairwise count(2) + n*4, AKM count(2) + n*4, capabilities(2), then an
 * optional group management cipher suite(4) when PMF is in use.
 */
static bool parse_rsn(const uint8_t *ie, unsigned len, ap_security_t *out)
{
    if (len < 8) return false;

    unsigned pos = 2;                       /* version */
    pos += 4;                               /* group data cipher suite */

    if (pos + 2 > len) return false;
    unsigned pairwise_count = (unsigned) ie[pos] | ((unsigned) ie[pos + 1] << 8);
    pos += 2;
    if (pos + pairwise_count * 4 > len) return false;
    pos += pairwise_count * 4;

    if (pos + 2 > len) return false;
    unsigned akm_count = (unsigned) ie[pos] | ((unsigned) ie[pos + 1] << 8);
    pos += 2;
    if (pos + akm_count * 4 > len) return false;
    pos += akm_count * 4;

    if (pos + 2 > len) {
        /* No capabilities field: PMF cannot be advertised. */
        out->pmf = AP_PMF_NONE;
        return true;
    }

    unsigned caps = (unsigned) ie[pos] | ((unsigned) ie[pos + 1] << 8);
    pos += 2;

    if (caps & RSN_CAP_MFPR) {
        out->pmf = AP_PMF_REQUIRED;
    } else if (caps & RSN_CAP_MFPC) {
        out->pmf = AP_PMF_CAPABLE;
    } else {
        out->pmf = AP_PMF_NONE;
    }

    /* A group management cipher suite only appears when PMF is enabled; it is
       stronger evidence than the capability bits alone. */
    if (pos + 4 <= len) {
        out->bip_cipher = true;
        if (out->pmf == AP_PMF_NONE) out->pmf = AP_PMF_CAPABLE;
    }

    return true;
}

bool wifictl_parse_ap_security(const uint8_t *frame, unsigned len, ap_security_t *out)
{
    if (frame == NULL || out == NULL || len < 36) return false;

    /* Only Beacon (8) and Probe Response (5) carry the full IE set. */
    uint8_t subtype = (frame[0] >> 4) & 0x0F;
    if (subtype != 8 && subtype != 5) return false;

    bool found_rsn = false;
    unsigned pos = 36;   /* 24-byte header + 12-byte fixed part */
    while (pos + 2 <= len) {
        uint8_t id = frame[pos];
        uint8_t ie_len = frame[pos + 1];
        if (pos + 2u + ie_len > len) break;

        const uint8_t *body = frame + pos + 2;
        if (id == IE_RSN) {
            found_rsn = parse_rsn(body, ie_len, out);
        } else if (id == IE_VENDOR && ie_len >= 4 &&
                   memcmp(body, WPS_OUI, sizeof(WPS_OUI)) == 0) {
            out->wps = true;
        } else if (id == IE_SSID) {
            /* nothing to do: the caller already knows the SSID */
        }

        pos += 2u + ie_len;
    }

    if (!found_rsn) {
        /* Open network or a Beacon without RSN: no PMF, no WPS. */
        out->pmf = AP_PMF_NONE;
    }
    ESP_LOGD(TAG, "PMF=%s bip=%d wps=%d", wifictl_pmf_name(out->pmf),
             (int) out->bip_cipher, (int) out->wps);
    return found_rsn;
}
