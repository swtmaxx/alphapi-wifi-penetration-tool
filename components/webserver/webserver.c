/**
 * @file webserver.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 *
 * @brief Implements Webserver component and all available enpoints.
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 *
 * Webserver is built on esp_http_server subcomponent from ESP-IDF
 * @see https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/protocols/esp_http_server.html
 */
#include "webserver.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "debug_log.h"
#include "attack.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

#include "pages/page_index.h"

static const char* TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

/**
 * @brief Headers that stop a browser from reinterpreting a response.
 *
 * Must be called before the response body is sent.
 */
static void set_security_headers(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
}

static const char *storage_state_name(pcap_storage_state_t state)
{
    switch (state) {
        case PCAP_STORAGE_OK: return "ok";
        case PCAP_STORAGE_MOUNT_ERROR: return "mount_error";
        case PCAP_STORAGE_FULL: return "full";
        case PCAP_STORAGE_IO_ERROR: return "io_error";
        default: return "unknown";
    }
}

/**
 * @brief Handlers for index/root \c / path endpoint
 *
 * This endpoint provides index page source
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_root_get_handler(httpd_req_t *req) {
    set_security_headers(req);
    /* The UI talks only to this device and needs no external resource, so keep
       the policy tight: even if injected markup ever reaches the DOM, it cannot
       load a remote script or exfiltrate captures. 'unsafe-inline' is required
       because the page ships its script and style inline. */
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       "default-src 'none'; script-src 'unsafe-inline'; "
                       "style-src 'unsafe-inline'; img-src 'none'; "
                       "connect-src 'self'; base-uri 'none'; "
                       "form-action 'none'; frame-ancestors 'none'");
    /* charset is required so the browser renders the Chinese UI correctly. */
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, (const char *)page_index, page_index_len);
}

static httpd_uri_t uri_root_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = uri_root_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /reset endpoint
 *
 * This endpoint resets the attack logic to initial READY state.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_reset_head_handler(httpd_req_t *req) {
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, NULL, 0, portMAX_DELAY));
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_reset_head = {
    .uri = "/reset",
    .method = HTTP_HEAD,
    .handler = uri_reset_head_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /ap-list endpoint
 *
 * This endpoint returns list of available APs nearby.
 * It calls wifi_controller ap_scanner and serialize their SSIDs into octet response.
 * @attention reponse may take few seconds
 * @attention client may be disconnected from ESP AP after calling this endpoint
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_ap_list_get_handler(httpd_req_t *req) {
    esp_err_t scan_ret = wifictl_scan_nearby_aps();
    if (scan_ret != ESP_OK) {
        const char *message = (scan_ret == ESP_ERR_TIMEOUT)
            ? "扫描正在进行，请稍候"
            : "扫描失败，请确认 Wi-Fi 状态后重试";
        /* ESP-IDF 5.0 does not define a 503 helper; retain the failure
           semantics with the closest standard server-error response. */
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, message);
    }

    wifictl_ap_records_t ap_records;
    if (!wifictl_copy_ap_records(&ap_records)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "无法读取扫描结果");
    }

    // 33 SSID + 6 BSSID + 1 RSSI + 1 client count
    char resp_chunk[41];

    set_security_headers(req);
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    for (unsigned i = 0; i < ap_records.count; i++) {
        memcpy(resp_chunk, ap_records.records[i].ssid, 33);
        memcpy(&resp_chunk[33], ap_records.records[i].bssid, 6);
        memcpy(&resp_chunk[39], &ap_records.records[i].rssi, 1);
        resp_chunk[40] = (char) wifictl_get_client_count(ap_records.records[i].bssid);
        ESP_ERROR_CHECK(httpd_resp_send_chunk(req, resp_chunk, 41));
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static httpd_uri_t uri_ap_list_get = {
    .uri = "/ap-list",
    .method = HTTP_GET,
    .handler = uri_ap_list_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /run-attack endpoint
 *
 * This endpoint receives attack configuration from client. It deserialize it from octet stream to attack_request_t structure.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_run_attack_post_handler(httpd_req_t *req) {
    attack_request_t attack_request;
    /* The body is exactly one attack_request_t. A shorter body would leave
       uninitialised stack bytes in the request that gets posted to the attack
       handler, so reject it instead of acting on garbage. */
    int received = httpd_req_recv(req, (char *)&attack_request, sizeof(attack_request_t));
    if (received == HTTPD_SOCK_ERR_TIMEOUT) {
        return httpd_resp_send_408(req);
    }
    if (received != (int) sizeof(attack_request_t)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "攻击参数不完整");
    }
    if (attack_request.type > ATTACK_TYPE_DOS) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "未知攻击类型");
    }
    esp_err_t res = httpd_resp_send(req, NULL, 0);
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST, &attack_request, sizeof(attack_request_t), portMAX_DELAY));
    return res;
}

static httpd_uri_t uri_run_attack_post = {
    .uri = "/run-attack",
    .method = HTTP_POST,
    .handler = uri_run_attack_post_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /status endpoint
 *
 * This endpoint fetches current status from main component attack wrapper, serialize it and sends it to client as octet stream.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_status_get_handler(httpd_req_t *req) {
    ESP_LOGD(TAG, "Fetching attack status...");
    attack_status_t attack_status;
    if (!attack_get_status_snapshot(&attack_status)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "status unavailable");
    }

    set_security_headers(req);
    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) {
        attack_free_status_snapshot(&attack_status);
        return res;
    }
    // first send attack result header
    res = httpd_resp_send_chunk(req, (char *) &attack_status, 4);
    // send attack result content
    if(res == ESP_OK && ((attack_status.state == FINISHED) ||
                         (attack_status.state == TIMEOUT) ||
                         (attack_status.state == STORAGE_ERROR)) &&
       (attack_status.content_size > 0)){
        res = httpd_resp_send_chunk(req, attack_status.content, attack_status.content_size);
    }
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, NULL, 0);
    attack_free_status_snapshot(&attack_status);
    return res;
}

static httpd_uri_t uri_status_get = {
    .uri = "/status",
    .method = HTTP_GET,
    .handler = uri_status_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /capture.pcap endpoint
 *
 * This endpoint forwards PCAP binary data from pcap_serializer via octet stream to client.
 *
 * @note Most browsers will start download process when this endpoint is called.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_capture_pcap_get_handler(httpd_req_t *req){
    ESP_LOGD(TAG, "Providing PCAP file...");
    set_security_headers(req);
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);

    unsigned total = pcap_serializer_get_size();
    uint8_t chunk[2048];
    unsigned offset = 0;
    esp_err_t res = ESP_OK;
    while (offset < total) {
        unsigned len = (total - offset) > sizeof(chunk) ? sizeof(chunk) : (total - offset);
        if (!pcap_serializer_read(offset, chunk, len)) {
            res = ESP_FAIL;
            break;
        }
        res = httpd_resp_send_chunk(req, (const char *)chunk, len);
        if (res != ESP_OK) break;
        offset += len;
    }
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, NULL, 0);
    return res;
}

static httpd_uri_t uri_capture_pcap_get = {
    .uri = "/capture.pcap",
    .method = HTTP_GET,
    .handler = uri_capture_pcap_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /capture.hccapx endpoint
 *
 * This endpoint forwards HCCAPX binary data from hccapx_serializer via octet stream to client.
 *
 * @note Most browsers will start download process when this endpoint is called.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_capture_hccapx_get_handler(httpd_req_t *req){
    ESP_LOGD(TAG, "Providing HCCAPX file...");
    /* hccapx_serializer_get() returns NULL until a usable handshake has been
       assembled: never hand a NULL buffer to the HTTP layer. */
    hccapx_t *hccapx = hccapx_serializer_get();
    if (hccapx == NULL) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "尚未抓到可用握手");
    }
    set_security_headers(req);
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    return httpd_resp_send(req, (char *) hccapx, sizeof(hccapx_t));
}

static httpd_uri_t uri_capture_hccapx_get = {
    .uri = "/capture.hccapx",
    .method = HTTP_GET,
    .handler = uri_capture_hccapx_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /pcap-list endpoint
 *
 * Returns a JSON array describing every stored capture file so the UI can
 * offer per-file and bulk download.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_pcap_list_get_handler(httpd_req_t *req) {
    pcap_file_info_t page[8];
    unsigned total = 0;
    if (!pcap_serializer_list_page(page, 8, 0, &total)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "无法读取抓包存储");
    }

    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_security_headers(req);
    esp_err_t res = httpd_resp_send_chunk(req, "[", 1);
    bool first = true;
    unsigned offset = 0;
    do {
        unsigned page_count = offset < total ? total - offset : 0;
        if (page_count > 8) page_count = 8;
        for (unsigned i = 0; i < page_count && res == ESP_OK; i++) {
            char chunk[128];
            int len = snprintf(chunk, sizeof(chunk), "%s{\"name\":\"%s\",\"size\":%u}",
                               first ? "" : ",", page[i].name, page[i].size);
            if (len < 0 || (size_t) len >= sizeof(chunk)) {
                res = ESP_FAIL;
                break;
            }
            res = httpd_resp_send_chunk(req, chunk, len);
            first = false;
        }
        offset += page_count;
        if (page_count == 0) break;
        if (offset < total && res == ESP_OK &&
            !pcap_serializer_list_page(page, 8, offset, &total)) {
            res = ESP_FAIL;
            break;
        }
    } while (offset < total && res == ESP_OK);
    if (res == ESP_OK) {
        res = httpd_resp_send_chunk(req, "]", 1);
    }
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, NULL, 0);
    return res;
}

static esp_err_t uri_storage_status_get_handler(httpd_req_t *req) {
    pcap_storage_info_t info;
    bool ok = pcap_serializer_get_storage_info(&info);
    char body[192];
    int len = snprintf(body, sizeof(body),
                       "{\"mounted\":%s,\"total\":%u,\"used\":%u,"
                       "\"free\":%u,\"state\":\"%s\"}",
                       info.mounted ? "true" : "false", info.total_bytes,
                       info.used_bytes, info.free_bytes,
                       storage_state_name(info.state));
    if (!ok && info.state == PCAP_STORAGE_OK) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "无法读取抓包存储状态");
    }
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_security_headers(req);
    return httpd_resp_send(req, body, len);
}

static httpd_uri_t uri_pcap_list_get = {
    .uri = "/pcap-list",
    .method = HTTP_GET,
    .handler = uri_pcap_list_get_handler,
    .user_ctx = NULL
};

static httpd_uri_t uri_storage_status_get = {
    .uri = "/storage-status",
    .method = HTTP_GET,
    .handler = uri_storage_status_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /capture-file endpoint
 *
 * Streams one stored capture file, selected by the \c name query parameter.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_capture_file_get_handler(httpd_req_t *req) {
    char query[96];
    char name[PCAP_FILENAME_MAX] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", name, sizeof(name)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "缺少文件参数");
    }

    pcap_file_info_t info;
    if (!pcap_serializer_get_file_info(name, &info)) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "文件不存在");
    }
    unsigned total = info.size;

    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    set_security_headers(req);
    char disposition[PCAP_FILENAME_MAX + 32];
    snprintf(disposition, sizeof(disposition), "attachment; filename=\"%s\"", name);
    httpd_resp_set_hdr(req, "Content-Disposition", disposition);

    uint8_t chunk[2048];
    unsigned offset = 0;
    esp_err_t res = ESP_OK;
    while (offset < total && res == ESP_OK) {
        unsigned len = (total - offset) > sizeof(chunk) ? sizeof(chunk) : (total - offset);
        if (!pcap_serializer_read_file(name, offset, chunk, len)) {
            res = ESP_FAIL;
            break;
        }
        res = httpd_resp_send_chunk(req, (const char *)chunk, len);
        offset += len;
    }
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, NULL, 0);
    return res;
}

static httpd_uri_t uri_capture_file_get = {
    .uri = "/capture-file",
    .method = HTTP_GET,
    .handler = uri_capture_file_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /pcap-delete endpoint
 *
 * Deletes one stored capture by the \c name query parameter.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_pcap_delete_post_handler(httpd_req_t *req) {
    char query[96];
    char name[PCAP_FILENAME_MAX] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", name, sizeof(name)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "缺少文件参数");
    }

    if (!pcap_serializer_delete(name)) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "删除失败或文件不存在");
    }
    return httpd_resp_sendstr(req, "OK");
}

static httpd_uri_t uri_pcap_delete_post = {
    .uri = "/pcap-delete",
    .method = HTTP_POST,
    .handler = uri_pcap_delete_post_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /pcap-delete-all endpoint
 *
 * Removes every stored capture and result file in one request.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_pcap_delete_all_post_handler(httpd_req_t *req) {
    unsigned removed = 0;
    bool ok = pcap_serializer_delete_all(&removed);

    char body[64];
    snprintf(body, sizeof(body), "%s已删除 %u 个文件",
             ok ? "" : "部分删除失败，", removed);
    return ok ? httpd_resp_sendstr(req, body) :
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, body);
}

static httpd_uri_t uri_pcap_delete_all_post = {
    .uri = "/pcap-delete-all",
    .method = HTTP_POST,
    .handler = uri_pcap_delete_all_post_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /count-clients endpoint
 *
 * Starts a passive client counting sweep in the background.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_count_clients_post_handler(httpd_req_t *req) {
    wifictl_start_client_counting();
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_count_clients_post = {
    .uri = "/count-clients",
    .method = HTTP_POST,
    .handler = uri_count_clients_post_handler,
    .user_ctx = NULL
};
//@}

static esp_err_t uri_count_clients_status_get_handler(httpd_req_t *req)
{
    char body[32];
    snprintf(body, sizeof(body), "{\"active\":%s}",
             wifictl_client_counting_active() ? "true" : "false");
    set_security_headers(req);
    esp_err_t res = httpd_resp_set_type(req, "application/json; charset=utf-8");
    if (res != ESP_OK) return res;
    return httpd_resp_sendstr(req, body);
}

static httpd_uri_t uri_count_clients_status_get = {
    .uri = "/count-clients/status",
    .method = HTTP_GET,
    .handler = uri_count_clients_status_get_handler,
    .user_ctx = NULL
};

/**
 * @brief Returns recent device logs captured since the last boot.
 */
static esp_err_t uri_logs_get_handler(httpd_req_t *req)
{
    char *buffer = malloc(DEBUG_LOG_EXPORT_MAX);
    if (buffer == NULL) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "日志缓冲区不足");
    }

    size_t length = debug_log_read(buffer, DEBUG_LOG_EXPORT_MAX);
    set_security_headers(req);
    esp_err_t res = httpd_resp_set_type(req, "text/plain; charset=utf-8");
    if (res == ESP_OK) res = httpd_resp_send(req, buffer, length);
    free(buffer);
    return res;
}

static httpd_uri_t uri_logs_get = {
    .uri = "/logs",
    .method = HTTP_GET,
    .handler = uri_logs_get_handler,
    .user_ctx = NULL
};

void webserver_run(){
    ESP_LOGD(TAG, "Running webserver");

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    /* The default cap (8) is below the number of endpoints registered here,
       and exceeding it makes httpd_register_uri_handler() fail. */
    config.max_uri_handlers = 16;
    /* Download handlers place a 2 KB stream chunk plus filename buffers on
       the stack, and the stdio read path runs on this same task; the default
       4 KB stack overflows and reboots the device mid-download. */
    config.stack_size = 8192;
    httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_reset_head));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ap_list_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_run_attack_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_pcap_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_hccapx_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_pcap_list_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_storage_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_file_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_pcap_delete_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_pcap_delete_all_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_count_clients_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_count_clients_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_logs_get));
}
