idf_component_register(SRCS "sniffer.c" "ap_scanner.c" "wifi_controller.c" "client_counter.c"
                    INCLUDE_DIRS "include"
                    PRIV_INCLUDE_DIRS "../frame_analyzer/include"
                    PRIV_REQUIRES esp_event esp_wifi)
