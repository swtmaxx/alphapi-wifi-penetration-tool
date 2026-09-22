/**
 * @file main.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Main file used to setup ESP32 into initial state
 *
 * @date Update 2023-05-07
 * @note Updated by Zheng Lin Lei
 * @note Github: https://github.com/ZhengLinLei
 * 
 * Starts management AP and webserver  
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_event.h"
#include "nvs_flash.h"

#include "attack.h"
#include "screen_ui.h"
#include "../components/wifi_controller/include/wifi_controller.h"
#include "../components/webserver/include/webserver.h"

void app_main(void)
{
    gpio_config_t bl = {
        .pin_bit_mask = 1ULL << 33,
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&bl);
    gpio_set_level(33, 1);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifictl_mgmt_ap_start();
    attack_init();
    webserver_run();
    screen_ui_init();
}
