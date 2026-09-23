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
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "attack.h"
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
    httpd_req_recv(req, (char *)&attack_request, sizeof(attack_request_t));
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

    esp_err_t res = httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    if (res != ESP_OK) {
        attack_free_status_snapshot(&attack_status);
        return res;
    }
    // first send attack result header
    res = httpd_resp_send_chunk(req, (char *) &attack_status, 4);
    // send attack result content
    if(res == ESP_OK && ((attack_status.state == FINISHED) || (attack_status.state == TIMEOUT)) && (attack_status.content_size > 0)){
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
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
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
 * Returns a JSON array describing every stored capture file so the UI can
 * offer per-file and bulk download.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_pcap_list_get_handler(httpd_req_t *req) {
    static pcap_file_info_t files[PCAP_LIST_MAX * 2];
    /* captures plus PMKID text results */
    unsigned count = pcap_serializer_list(files, PCAP_LIST_MAX);
    count += pcap_serializer_list_text(files + count, PCAP_LIST_MAX);

    httpd_resp_set_type(req, "application/json; charset=utf-8");
    esp_err_t res = httpd_resp_send_chunk(req, "[", 1);
    for (unsigned i = 0; i < count && res == ESP_OK; i++) {
        char chunk[96];
        int len = snprintf(chunk, sizeof(chunk), "%s{\"name\":\"%s\",\"size\":%u}",
                           i == 0 ? "" : ",", files[i].name, files[i].size);
        res = httpd_resp_send_chunk(req, chunk, len);
    }
    if (res == ESP_OK) res = httpd_resp_send_chunk(req, "]", 1);
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
    char query[96];
    char name[40] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", name, sizeof(name)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "缺少文件参数");
    }

    /* Resolve the stored size first so the final partial chunk is not lost. */
    static pcap_file_info_t files[PCAP_LIST_MAX * 2];
    unsigned count = pcap_serializer_list(files, PCAP_LIST_MAX);
    count += pcap_serializer_list_text(files + count, PCAP_LIST_MAX);
    unsigned total = 0;
    bool found = false;
    for (unsigned i = 0; i < count; i++) {
        if (strcmp(files[i].name, name) == 0) {
            total = files[i].size;
            found = true;
            break;
        }
    }
    if (!found) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "文件不存在");
    }

    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    char disposition[64];
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
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_count_clients_post));
}
