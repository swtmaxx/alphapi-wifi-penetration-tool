/**
 * @file screen_ui.c
 * @brief Chinese standalone UI for the AlphaPi display.
 */
#include "screen_ui.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_event.h"

#include "display.h"
#include "attack.h"
#include "hccapx_serializer.h"
#include "pcap_serializer.h"
#include "webserver.h"
#include "wifi_controller.h"

#define KEY_ENTER 13
#define KEY_BACK  12
#define KEY_UP    11
#define KEY_DOWN  10

#define RENDER_PERIOD_MS 150
#define UI_TASK_STACK    7168
#define UI_TASK_PRIO     3
#define HEADER_H         16
#define CONTENT_Y        16
#define LINE_H           16
#define FOOTER_Y         112
#define AP_VISIBLE        6
#define RESULT_BYTES_PAGE 24

typedef enum {
    SCREEN_MAIN_MENU,
    SCREEN_STATUS,
    SCREEN_AP_LIST,
    SCREEN_ATTACK_TYPE,
    SCREEN_ATTACK_METHOD,
    SCREEN_ATTACK_TIMEOUT,
    SCREEN_ATTACK_CONFIRM,
    SCREEN_ATTACK_STATUS,
    SCREEN_RESULT,
    SCREEN_CAPTURE
} screen_id_t;

typedef enum {
    SCAN_IDLE,
    SCAN_PENDING,
    SCAN_RUNNING,
    SCAN_READY,
    SCAN_FAILED
} scan_state_t;

typedef struct {
    screen_id_t screen;
    uint8_t menu_index;
    uint8_t ap_index;
    uint8_t atk_type;
    uint8_t atk_method;
    uint8_t atk_timeout_index;
    uint8_t atk_timeout_seconds;
    uint16_t result_page;
    scan_state_t scan_state;
    esp_err_t scan_error;
    bool dirty;
} ui_state_t;

static ui_state_t ui;
static const char *UI_TAG = "screen_ui";

static const char *main_menu_items[] = {
    "状态", "网络扫描", "攻击结果", "抓包文件"
};
#define MAIN_MENU_COUNT 4

static const char *attack_type_names[] = {
    "被动", "握手", "PMKID", "拒绝服务"
};
#define ATTACK_TYPE_COUNT 4

static const char *handshake_method_names[] = {
    "诱骗 AP", "广播去认证", "仅抓包"
};
#define HANDSHAKE_METHOD_COUNT 3

static const char *dos_method_names[] = {
    "诱骗 AP", "广播去认证", "全部组合"
};
#define DOS_METHOD_COUNT 3

static const uint8_t timeout_values[] = {0, 10, 30, 60, 120};
static const char *timeout_names[] = {"无限", "10 秒", "30 秒", "60 秒", "120 秒"};
#define TIMEOUT_COUNT 5

static const char *attack_state_name(uint8_t state)
{
    switch (state) {
        case READY: return "空闲";
        case RUNNING: return "运行中";
        case FINISHED: return "完成";
        case TIMEOUT: return "超时";
        default: return "未知";
    }
}

static uint8_t method_count(void)
{
    if (ui.atk_type == ATTACK_TYPE_HANDSHAKE) return HANDSHAKE_METHOD_COUNT;
    if (ui.atk_type == ATTACK_TYPE_DOS) return DOS_METHOD_COUNT;
    return 1;
}

static const char *method_name(uint8_t index)
{
    if (ui.atk_type == ATTACK_TYPE_HANDSHAKE) {
        return index < HANDSHAKE_METHOD_COUNT ? handshake_method_names[index] : "-";
    }
    if (ui.atk_type == ATTACK_TYPE_DOS) {
        return index < DOS_METHOD_COUNT ? dos_method_names[index] : "-";
    }
    return "-";
}

static bool copy_records(wifictl_ap_records_t *records)
{
    return wifictl_copy_ap_records(records);
}

static void draw_header(const char *title)
{
    display_fill_rect(0, 0, DISPLAY_WIDTH, HEADER_H, COLOR_BLUE);
    display_draw_text_utf8(3, 0, title, COLOR_WHITE, COLOR_BLUE);
}

static void draw_footer(const char *hint)
{
    display_fill_rect(0, FOOTER_Y, DISPLAY_WIDTH, DISPLAY_HEIGHT - FOOTER_Y, COLOR_DARKGRAY);
    display_draw_text_utf8(3, FOOTER_Y, hint, COLOR_WHITE, COLOR_DARKGRAY);
}

static void draw_menu_list(const char *const *items, uint8_t count, uint8_t selected)
{
    int16_t y = CONTENT_Y;
    for (uint8_t i = 0; i < count; i++) {
        uint16_t fg = i == selected ? COLOR_BLACK : COLOR_WHITE;
        uint16_t bg = i == selected ? COLOR_YELLOW : COLOR_BLACK;
        display_fill_rect(1, y, DISPLAY_WIDTH - 2, LINE_H, bg);
        display_draw_text_utf8(5, y, items[i], fg, bg);
        y += LINE_H;
    }
}

static void draw_main_menu(void)
{
    draw_menu_list(main_menu_items, MAIN_MENU_COUNT, ui.menu_index);
    draw_footer("确定=进入");
}

static void draw_status(void)
{
    char buf[32];
    attack_status_t status;
    wifictl_ap_records_t records;

    display_draw_text_utf8(3, CONTENT_Y, "AlphaPi", COLOR_GREEN, COLOR_BLACK);
    display_draw_text_utf8(3, CONTENT_Y + LINE_H, "芯片 ESP32-S2", COLOR_WHITE, COLOR_BLACK);
    if (copy_records(&records)) {
        snprintf(buf, sizeof(buf), "AP 数量 %u", records.count);
        display_draw_text_utf8(3, CONTENT_Y + 2 * LINE_H, buf, COLOR_YELLOW, COLOR_BLACK);
    }
    if (attack_get_status_snapshot(&status)) {
        snprintf(buf, sizeof(buf), "攻击 %s", attack_state_name(status.state));
        display_draw_text_utf8(3, CONTENT_Y + 3 * LINE_H, buf,
                               status.state == RUNNING ? COLOR_ORANGE : COLOR_WHITE,
                               COLOR_BLACK);
        attack_free_status_snapshot(&status);
    }
    draw_footer("返回=菜单");
}

static void draw_scan_message(void)
{
    if (ui.scan_state == SCAN_RUNNING || ui.scan_state == SCAN_PENDING) {
        display_draw_text_utf8(3, CONTENT_Y, "正在扫描网络", COLOR_YELLOW, COLOR_BLACK);
        display_draw_text_utf8(3, CONTENT_Y + LINE_H, "请稍候", COLOR_WHITE, COLOR_BLACK);
        draw_footer("返回=菜单");
        return;
    }
    if (ui.scan_state == SCAN_FAILED) {
        display_draw_text_utf8(3, CONTENT_Y, "扫描失败", COLOR_RED, COLOR_BLACK);
        if (ui.scan_error == ESP_ERR_TIMEOUT) {
            display_draw_text_utf8(3, CONTENT_Y + LINE_H, "扫描正在进行", COLOR_WHITE, COLOR_BLACK);
        } else if (ui.scan_error == ESP_ERR_INVALID_STATE) {
            display_draw_text_utf8(3, CONTENT_Y + LINE_H, "攻击中无法扫描", COLOR_WHITE, COLOR_BLACK);
        } else {
            display_draw_text_utf8(3, CONTENT_Y + LINE_H, "请重试", COLOR_WHITE, COLOR_BLACK);
        }
    }
}

static void draw_ap_list(void)
{
    wifictl_ap_records_t records;
    char buf[24];
    int16_t y = CONTENT_Y;
    uint8_t shown = 0;

    if (ui.scan_state == SCAN_RUNNING || ui.scan_state == SCAN_PENDING ||
        ui.scan_state == SCAN_FAILED) {
        draw_scan_message();
        return;
    }
    if (!copy_records(&records) || records.count == 0) {
        display_draw_text_utf8(3, y, "未发现网络", COLOR_GRAY, COLOR_BLACK);
        draw_footer("返回=菜单");
        return;
    }
    if (ui.ap_index >= records.count) ui.ap_index = records.count - 1;

    uint8_t scroll = ui.ap_index >= AP_VISIBLE ? ui.ap_index - AP_VISIBLE + 1 : 0;
    for (uint8_t i = scroll; i < records.count && shown < AP_VISIBLE; i++, shown++) {
        const wifi_ap_record_t *record = &records.records[i];
        char ssid[33];
        memcpy(ssid, record->ssid, sizeof(ssid));
        ssid[32] = '\0';
        if (ssid[0] == '\0') strcpy(ssid, "(隐藏)");
        uint16_t fg = i == ui.ap_index ? COLOR_BLACK : COLOR_WHITE;
        uint16_t bg = i == ui.ap_index ? COLOR_YELLOW : COLOR_BLACK;
        display_fill_rect(1, y, DISPLAY_WIDTH - 2, LINE_H, bg);
        display_draw_text_utf8(4, y, ssid, fg, bg);
        snprintf(buf, sizeof(buf), "%d %d", record->primary, record->rssi);
        display_draw_text(123, y, buf, fg, bg);
        y += LINE_H;
    }
    draw_footer("确定=攻击 返回=菜单");
}

static void draw_attack_type(void)
{
    draw_menu_list(attack_type_names, ATTACK_TYPE_COUNT, ui.menu_index);
    draw_footer("确定=下一步 返回=返回");
}

static void draw_attack_method(void)
{
    const char *names[3];
    uint8_t count = method_count();
    for (uint8_t i = 0; i < count; i++) names[i] = method_name(i);
    draw_menu_list(names, count, ui.menu_index);
    draw_footer("确定=下一步 返回=返回");
}

static void draw_timeout(void)
{
    draw_menu_list(timeout_names, TIMEOUT_COUNT, ui.menu_index);
    draw_footer("确定=下一步 返回=返回");
}

static void draw_attack_confirm(void)
{
    char buf[32];
    wifictl_ap_records_t records;
    int16_t y = CONTENT_Y;
    const wifi_ap_record_t *record = NULL;
    if (copy_records(&records) && ui.ap_index < records.count) record = &records.records[ui.ap_index];

    display_draw_text_utf8(3, y, "确认攻击", COLOR_YELLOW, COLOR_BLACK);
    y += LINE_H;
    if (record) {
        char ssid[33];
        memcpy(ssid, record->ssid, sizeof(ssid));
        ssid[32] = '\0';
        display_draw_text_utf8(3, y, ssid[0] ? ssid : "(隐藏)", COLOR_CYAN, COLOR_BLACK);
    } else {
        display_draw_text_utf8(3, y, "未选择目标", COLOR_RED, COLOR_BLACK);
    }
    y += LINE_H;
    snprintf(buf, sizeof(buf), "类型 %s", attack_type_names[ui.atk_type]);
    display_draw_text_utf8(3, y, buf, COLOR_WHITE, COLOR_BLACK);
    y += LINE_H;
    snprintf(buf, sizeof(buf), "超时 %s", timeout_names[ui.atk_timeout_index]);
    display_draw_text_utf8(3, y, buf, COLOR_WHITE, COLOR_BLACK);
    draw_footer("确定=开始 返回=取消");
}

static void draw_hex_page(const uint8_t *data, unsigned size)
{
    char line[24];
    unsigned offset = (unsigned)ui.result_page * RESULT_BYTES_PAGE;
    for (unsigned row = 0; row < 3 && offset < size; row++) {
        unsigned count = size - offset;
        if (count > 6) count = 6;
        unsigned pos = 0;
        for (unsigned i = 0; i < count; i++) {
            pos += (unsigned)snprintf(&line[pos], sizeof(line) - pos, "%02X ", data[offset + i]);
        }
        line[pos] = '\0';
        display_draw_text(3, CONTENT_Y + 3 * LINE_H + (int16_t)row * LINE_H, line, COLOR_CYAN, COLOR_BLACK);
        offset += count;
    }
}

static void draw_attack_status(void)
{
    attack_status_t status;
    char buf[32];
    if (!attack_get_status_snapshot(&status)) return;
    snprintf(buf, sizeof(buf), "状态 %s", attack_state_name(status.state));
    display_draw_text_utf8(3, CONTENT_Y, buf,
                           status.state == RUNNING ? COLOR_ORANGE : COLOR_WHITE,
                           COLOR_BLACK);
    snprintf(buf, sizeof(buf), "类型 %s",
             status.type < ATTACK_TYPE_COUNT ? attack_type_names[status.type] : "-");
    display_draw_text_utf8(3, CONTENT_Y + LINE_H, buf, COLOR_WHITE, COLOR_BLACK);
    if (status.content != NULL && status.content_size > 0) {
        snprintf(buf, sizeof(buf), "数据 %u 字节", status.content_size);
        display_draw_text_utf8(3, CONTENT_Y + 2 * LINE_H, buf, COLOR_CYAN, COLOR_BLACK);
    }
    attack_free_status_snapshot(&status);
    draw_footer("返回=停止");
}

static void draw_result(void)
{
    attack_status_t status;
    char buf[32];
    if (!attack_get_status_snapshot(&status)) return;
    display_draw_text_utf8(3, CONTENT_Y, "攻击结果", COLOR_YELLOW, COLOR_BLACK);
    snprintf(buf, sizeof(buf), "状态 %s", attack_state_name(status.state));
    display_draw_text_utf8(3, CONTENT_Y + LINE_H, buf, COLOR_WHITE, COLOR_BLACK);
    if (status.content != NULL && status.content_size > 0) {
        unsigned pages = (status.content_size + RESULT_BYTES_PAGE - 1) / RESULT_BYTES_PAGE;
        if (pages == 0) pages = 1;
        if (ui.result_page >= pages) ui.result_page = pages - 1;
        snprintf(buf, sizeof(buf), "第 %u/%u 页", ui.result_page + 1, pages);
        display_draw_text_utf8(3, CONTENT_Y + 2 * LINE_H, buf, COLOR_WHITE, COLOR_BLACK);
        draw_hex_page((const uint8_t *)status.content, status.content_size);
    } else {
        display_draw_text_utf8(3, CONTENT_Y + 2 * LINE_H, "暂无结果", COLOR_GRAY, COLOR_BLACK);
    }
    attack_free_status_snapshot(&status);
    draw_footer("上下=翻页 返回=菜单");
}

static void draw_capture(void)
{
    char buf[32];
    hccapx_t *hccapx = hccapx_serializer_get();
    display_draw_text_utf8(3, CONTENT_Y, "抓包文件", COLOR_YELLOW, COLOR_BLACK);
    snprintf(buf, sizeof(buf), "PCAP %u 字节", pcap_serializer_get_size());
    display_draw_text_utf8(3, CONTENT_Y + LINE_H, buf, COLOR_WHITE, COLOR_BLACK);
    display_draw_text_utf8(3, CONTENT_Y + 2 * LINE_H,
                           hccapx ? "HCCAPX 可用" : "HCCAPX 暂无",
                           hccapx ? COLOR_GREEN : COLOR_GRAY, COLOR_BLACK);
    display_draw_text_utf8(3, CONTENT_Y + 3 * LINE_H, "文件保存在 Flash", COLOR_GRAY, COLOR_BLACK);
    draw_footer("返回=菜单");
}

static void render(void)
{
    display_fill(COLOR_BLACK);
    switch (ui.screen) {
        case SCREEN_MAIN_MENU: draw_header("主菜单"); draw_main_menu(); break;
        case SCREEN_STATUS: draw_header("状态"); draw_status(); break;
        case SCREEN_AP_LIST: draw_header("网络扫描"); draw_ap_list(); break;
        case SCREEN_ATTACK_TYPE: draw_header("攻击类型"); draw_attack_type(); break;
        case SCREEN_ATTACK_METHOD: draw_header("攻击方式"); draw_attack_method(); break;
        case SCREEN_ATTACK_TIMEOUT: draw_header("攻击超时"); draw_timeout(); break;
        case SCREEN_ATTACK_CONFIRM: draw_header("确认攻击"); draw_attack_confirm(); break;
        case SCREEN_ATTACK_STATUS: draw_header("攻击状态"); draw_attack_status(); break;
        case SCREEN_RESULT: draw_header("攻击结果"); draw_result(); break;
        case SCREEN_CAPTURE: draw_header("抓包文件"); draw_capture(); break;
        default: break;
    }
    display_flush();
}

static bool key_pressed(gpio_num_t pin, int *last_level)
{
    int level = gpio_get_level(pin);
    bool pressed = *last_level == 1 && level == 0;
    *last_level = level;
    return pressed;
}

static bool has_ap_records(void)
{
    wifictl_ap_records_t records;
    return copy_records(&records) && records.count > 0;
}

static void request_scan(void)
{
    ui.scan_state = SCAN_PENDING;
    ui.scan_error = ESP_OK;
}

static void run_pending_scan(void)
{
    if (ui.scan_state != SCAN_PENDING) return;
    ui.scan_state = SCAN_RUNNING;
    ui.dirty = true;
    render();
    vTaskDelay(pdMS_TO_TICKS(50));

    attack_status_t status;
    if (attack_get_status_snapshot(&status)) {
        bool running = status.state == RUNNING;
        attack_free_status_snapshot(&status);
        if (running) {
            ui.scan_error = ESP_ERR_INVALID_STATE;
            ui.scan_state = SCAN_FAILED;
            ui.dirty = true;
            return;
        }
    }

    ui.scan_error = wifictl_scan_nearby_aps();
    ui.scan_state = ui.scan_error == ESP_OK ? SCAN_READY : SCAN_FAILED;
    ui.ap_index = 0;
    ui.dirty = true;
}

static void handle_enter(void)
{
    switch (ui.screen) {
        case SCREEN_MAIN_MENU:
            switch (ui.menu_index) {
                case 0: ui.screen = SCREEN_STATUS; break;
                case 1: ui.screen = SCREEN_AP_LIST; request_scan(); break;
                case 2: ui.screen = SCREEN_RESULT; ui.result_page = 0; break;
                case 3: ui.screen = SCREEN_CAPTURE; break;
                default: break;
            }
            break;
        case SCREEN_AP_LIST:
            if (has_ap_records()) {
                ui.screen = SCREEN_ATTACK_TYPE;
                ui.menu_index = ui.atk_type;
            }
            break;
        case SCREEN_STATUS:
            ui.screen = SCREEN_MAIN_MENU;
            ui.menu_index = 0;
            break;
        case SCREEN_ATTACK_TYPE:
            ui.atk_type = ui.menu_index;
            if (ui.atk_type == ATTACK_TYPE_HANDSHAKE || ui.atk_type == ATTACK_TYPE_DOS) {
                ui.screen = SCREEN_ATTACK_METHOD;
                ui.menu_index = ui.atk_method;
            } else {
                ui.atk_method = 0;
                ui.screen = SCREEN_ATTACK_TIMEOUT;
                ui.menu_index = ui.atk_timeout_index;
            }
            break;
        case SCREEN_ATTACK_METHOD:
            ui.atk_method = ui.menu_index;
            ui.screen = SCREEN_ATTACK_TIMEOUT;
            ui.menu_index = ui.atk_timeout_index;
            break;
        case SCREEN_ATTACK_TIMEOUT:
            ui.atk_timeout_index = ui.menu_index;
            ui.atk_timeout_seconds = timeout_values[ui.menu_index];
            ui.screen = SCREEN_ATTACK_CONFIRM;
            break;
        case SCREEN_ATTACK_CONFIRM: {
            attack_request_t request = {
                .ap_record_id = ui.ap_index,
                .type = ui.atk_type,
                .method = ui.atk_method,
                .timeout = ui.atk_timeout_seconds,
            };
            esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST,
                           &request, sizeof(request), portMAX_DELAY);
            ui.screen = SCREEN_ATTACK_STATUS;
            break;
        }
        default: break;
    }
}

static void handle_back(void)
{
    switch (ui.screen) {
        case SCREEN_MAIN_MENU: break;
        case SCREEN_AP_LIST:
        case SCREEN_RESULT:
        case SCREEN_CAPTURE:
        case SCREEN_STATUS:
            ui.screen = SCREEN_MAIN_MENU;
            ui.menu_index = 0;
            break;
        case SCREEN_ATTACK_STATUS:
            esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, NULL, 0, portMAX_DELAY);
            ui.screen = SCREEN_RESULT;
            ui.result_page = 0;
            break;
        case SCREEN_ATTACK_TYPE:
        case SCREEN_ATTACK_METHOD:
        case SCREEN_ATTACK_TIMEOUT:
        case SCREEN_ATTACK_CONFIRM:
            ui.screen = SCREEN_AP_LIST;
            break;
        default: break;
    }
}

static void handle_up(void)
{
    switch (ui.screen) {
        case SCREEN_MAIN_MENU:
            ui.menu_index = (ui.menu_index + MAIN_MENU_COUNT - 1) % MAIN_MENU_COUNT;
            break;
        case SCREEN_AP_LIST: if (ui.ap_index > 0) ui.ap_index--; break;
        case SCREEN_ATTACK_TYPE:
            ui.menu_index = (ui.menu_index + ATTACK_TYPE_COUNT - 1) % ATTACK_TYPE_COUNT;
            break;
        case SCREEN_ATTACK_METHOD:
            ui.menu_index = (ui.menu_index + method_count() - 1) % method_count();
            break;
        case SCREEN_ATTACK_TIMEOUT:
            ui.menu_index = (ui.menu_index + TIMEOUT_COUNT - 1) % TIMEOUT_COUNT;
            break;
        case SCREEN_RESULT: if (ui.result_page > 0) ui.result_page--; break;
        default: break;
    }
}

static void handle_down(void)
{
    switch (ui.screen) {
        case SCREEN_MAIN_MENU:
            ui.menu_index = (ui.menu_index + 1) % MAIN_MENU_COUNT;
            break;
        case SCREEN_AP_LIST: {
            wifictl_ap_records_t records;
            if (copy_records(&records) && ui.ap_index + 1 < records.count) ui.ap_index++;
            break;
        }
        case SCREEN_ATTACK_TYPE:
            ui.menu_index = (ui.menu_index + 1) % ATTACK_TYPE_COUNT;
            break;
        case SCREEN_ATTACK_METHOD:
            ui.menu_index = (ui.menu_index + 1) % method_count();
            break;
        case SCREEN_ATTACK_TIMEOUT:
            ui.menu_index = (ui.menu_index + 1) % TIMEOUT_COUNT;
            break;
        case SCREEN_RESULT: ui.result_page++; break;
        default: break;
    }
}

static void ui_task(void *arg)
{
    int level_enter = 1, level_back = 1, level_up = 1, level_down = 1;
    (void)arg;
    render();
    ui.dirty = false;

    while (1) {
        if (key_pressed(KEY_ENTER, &level_enter)) { handle_enter(); ui.dirty = true; }
        if (key_pressed(KEY_BACK, &level_back)) { handle_back(); ui.dirty = true; }
        if (key_pressed(KEY_UP, &level_up)) { handle_up(); ui.dirty = true; }
        if (key_pressed(KEY_DOWN, &level_down)) { handle_down(); ui.dirty = true; }

        if (ui.dirty) {
            render();
            ui.dirty = false;
        }
        run_pending_scan();
        if (ui.screen == SCREEN_ATTACK_STATUS || ui.screen == SCREEN_CAPTURE) {
            ui.dirty = true;
        }
        vTaskDelay(pdMS_TO_TICKS(RENDER_PERIOD_MS));
    }
}

void screen_ui_init(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << KEY_ENTER) | (1ULL << KEY_BACK) |
                        (1ULL << KEY_UP) | (1ULL << KEY_DOWN),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);

    memset(&ui, 0, sizeof(ui));
    ui.screen = SCREEN_MAIN_MENU;
    ui.atk_type = ATTACK_TYPE_PMKID;
    ui.atk_timeout_index = 2;
    ui.atk_timeout_seconds = timeout_values[ui.atk_timeout_index];
    ui.scan_state = SCAN_IDLE;
    ui.dirty = true;

    display_init();
    if (xTaskCreate(ui_task, "screen_ui", UI_TASK_STACK, NULL, UI_TASK_PRIO, NULL) != pdPASS) {
        printf("[%s] failed to create ui task\n", UI_TAG);
    }
}
