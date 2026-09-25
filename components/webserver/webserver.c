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
#include "attack_handshake.h"
#include "attack_dos.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

#include "pages/page_index.h"

static const char* TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

/**
 * @brief Handlers for index/root \c / path endpoint
 *
 * This endpoint provides index page source
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_root_get_handler(httpd_req_t *req) {
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
    esp_err_t err = esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET,
                                   NULL, 0, pdMS_TO_TICKS(100));
    if (err != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "设备正忙，请稍后重试");
    }
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

    // 33 SSID + 6 BSSID + 1 RSSI. Client counts are intentionally omitted.
    char resp_chunk[40];

    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) return res;
    for (unsigned i = 0; i < ap_records.count; i++) {
        memcpy(resp_chunk, ap_records.records[i].ssid, 33);
        memcpy(&resp_chunk[33], ap_records.records[i].bssid, 6);
        memcpy(&resp_chunk[39], &ap_records.records[i].rssi, 1);
        res = httpd_resp_send_chunk(req, resp_chunk, sizeof(resp_chunk));
        if (res != ESP_OK) return res;
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
    if (req->content_len != sizeof(attack_request_t)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "攻击参数长度无效");
    }

    attack_request_t attack_request;
    size_t received = 0;
    while (received < sizeof(attack_request)) {
        int result = httpd_req_recv(req, (char *)&attack_request + received,
                                    sizeof(attack_request) - received);
        if (result <= 0) {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "未能读取完整攻击参数");
        }
        received += (size_t)result;
    }

    bool valid_type = attack_request.type >= ATTACK_TYPE_HANDSHAKE &&
                      attack_request.type <= ATTACK_TYPE_DOS;
    bool valid_method = (attack_request.type == ATTACK_TYPE_HANDSHAKE &&
                         attack_request.method <= ATTACK_HANDSHAKE_METHOD_PASSIVE) ||
                        (attack_request.type == ATTACK_TYPE_PMKID &&
                         attack_request.method == 0) ||
                        (attack_request.type == ATTACK_TYPE_DOS &&
                         attack_request.method <= ATTACK_DOS_METHOD_COMBINE_ALL);
    if (!valid_type || !valid_method) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "攻击类型或方式无效");
    }

    esp_err_t err = esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST,
                                   &attack_request, sizeof(attack_request),
                                   pdMS_TO_TICKS(100));
    if (err != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "设备正忙，请稍后重试");
    }
    return httpd_resp_send(req, NULL, 0);
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

    uint8_t header[4] = {
        attack_status.state,
        attack_status.type,
        (uint8_t)(attack_status.content_size & 0xff),
        (uint8_t)(attack_status.content_size >> 8)
    };
    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) {
        attack_free_status_snapshot(&attack_status);
        return res;
    }
    res = httpd_resp_send_chunk(req, (const char *)header, sizeof(header));
    // send attack result content
    if(res == ESP_OK && (attack_status.state == FINISHED ||
                         attack_status.state == TIMEOUT ||
                         attack_status.state == ERROR) &&
       attack_status.content_size > 0){
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
    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) return res;

    unsigned total = pcap_serializer_get_size();
    uint8_t chunk[2048];
    unsigned offset = 0;
    res = ESP_OK;
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
    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) return res;
    return httpd_resp_send(req, (char *) hccapx_serializer_get(), sizeof(hccapx_t));
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
 * Returns one bounded page of stored files and the total count.
 * @param req
 * @return esp_err_t
 * @{
 */
static bool parse_optional_uint(const char *query, const char *key,
                                unsigned default_value, unsigned max_value,
                                unsigned *out)
{
    char value[16];
    esp_err_t err = httpd_query_key_value(query, key, value, sizeof(value));
    if (err == ESP_ERR_NOT_FOUND) {
        *out = default_value;
        return true;
    }
    if (err != ESP_OK || value[0] == '\0') return false;

    unsigned parsed = 0;
    for (const char *p = value; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (parsed > (max_value - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed > max_value) return false;
    *out = parsed;
    return true;
}

static bool safe_stored_name(const char *name)
{
    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) {
            return false;
        }
    }
    return true;
}

static esp_err_t send_json_name(httpd_req_t *req, const char *name)
{
    char escaped[PCAP_FILENAME_MAX * 6 + 1];
    size_t used = 0;
    static const char hex[] = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++) {
        if (*p == '"' || *p == '\\') {
            escaped[used++] = '\\';
            escaped[used++] = (char)*p;
        } else if (*p < 0x20) {
            escaped[used++] = '\\';
            escaped[used++] = 'u';
            escaped[used++] = '0';
            escaped[used++] = '0';
            escaped[used++] = hex[*p >> 4];
            escaped[used++] = hex[*p & 0x0f];
        } else {
            escaped[used++] = (char)*p;
        }
    }
    return httpd_resp_send_chunk(req, escaped, used);
}

static esp_err_t uri_pcap_list_get_handler(httpd_req_t *req)
{
    char query[96] = "";
    unsigned offset = 0;
    unsigned limit = 16;
    int query_result = httpd_req_get_url_query_str(req, query, sizeof(query));
    if (query_result != ESP_OK && query_result != ESP_ERR_NOT_FOUND) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "分页参数过长");
    }
    if (!parse_optional_uint(query, "offset", 0, 1000000, &offset) ||
        !parse_optional_uint(query, "limit", 16, PCAP_LIST_MAX, &limit) ||
        limit == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "分页参数无效");
    }

    static pcap_file_info_t files[PCAP_LIST_MAX];
    unsigned total = 0;
    if (!pcap_serializer_list_page(files, limit, offset, &total)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "无法读取文件列表");
    }

    esp_err_t res = httpd_resp_set_type(req, "application/json; charset=utf-8");
    if (res != ESP_OK) return res;
    char head[96];
    int head_len = snprintf(head, sizeof(head),
                            "{\"total\":%u,\"offset\":%u,\"limit\":%u,\"files\":[",
                            total, offset, limit);
    res = httpd_resp_send_chunk(req, head, head_len);
    for (unsigned i = 0; i < limit && offset + i < total && res == ESP_OK; i++) {
        char prefix[16];
        int prefix_len = snprintf(prefix, sizeof(prefix), "%s{\"name\":\"",
                                  i == 0 ? "" : ",");
        res = httpd_resp_send_chunk(req, prefix, prefix_len);
        if (res == ESP_OK) res = send_json_name(req, files[i].name);
        if (res == ESP_OK) {
            char suffix[32];
            int suffix_len = snprintf(suffix, sizeof(suffix), "\",\"size\":%u}", files[i].size);
            res = httpd_resp_send_chunk(req, suffix, suffix_len);
        }
    }
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, "]}", 2);
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, NULL, 0);
    return res;
}

static httpd_uri_t uri_pcap_list_get = {
    .uri = "/pcap-list",
    .method = HTTP_GET,
    .handler = uri_pcap_list_get_handler,
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
    char query[128];
    char name[PCAP_FILENAME_MAX] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", name, sizeof(name)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "缺少文件参数");
    }

    /* Resolve the stored size first so the final partial chunk is not lost. */
    pcap_file_info_t info;
    if (!safe_stored_name(name) || !pcap_serializer_get_file_info(name, &info)) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "文件不存在");
    }
    unsigned total = info.size;

    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) return res;
    char disposition[PCAP_FILENAME_MAX + 32];
    snprintf(disposition, sizeof(disposition), "attachment; filename=\"%s\"", name);
    res = httpd_resp_set_hdr(req, "Content-Disposition", disposition);
    if (res != ESP_OK) return res;

    uint8_t chunk[2048];
    unsigned offset = 0;
    res = ESP_OK;
    while (offset < total && res == ESP_OK) {
        unsigned len = (total - offset) > sizeof(chunk) ? sizeof(chunk) : (total - offset);
        if (!pcap_serializer_read_file(name, offset, chunk, len)) {
            res = ESP_FAIL;
            break;
        }
        res = httpd_resp_send_chunk(req, (const char *)chunk, len);
        if (res == ESP_OK) offset += len;
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
    char query[128];
    char name[PCAP_FILENAME_MAX] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", name, sizeof(name)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "缺少文件参数");
    }

    if (!safe_stored_name(name) || !pcap_serializer_delete(name)) {
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
    if (!pcap_serializer_delete_all(&removed)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "删除文件失败");
    }

    char body[48];
    snprintf(body, sizeof(body), "已删除 %u 个文件", removed);
    return httpd_resp_sendstr(req, body);
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
    if (!wifictl_start_client_counting()) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "客户端探测无法启动或正在运行");
    }
    esp_err_t res = httpd_resp_set_type(req, "application/json; charset=utf-8");
    if (res != ESP_OK) return res;
    return httpd_resp_sendstr(req, "{\"active\":true}");
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
    esp_err_t res = httpd_resp_set_type(req, "text/plain; charset=utf-8");
    if (res == ESP_OK) res = httpd_resp_set_hdr(req, "Cache-Control", "no-store");
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
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_file_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_pcap_delete_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_pcap_delete_all_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_count_clients_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_count_clients_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_logs_get));
}
