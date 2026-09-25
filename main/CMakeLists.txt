idf_component_register(SRCS "attack_dos.c" "attack_method.c" "main.c" "attack_handshake.c" "attack_pmkid.c" "attack.c" "screen_ui.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES wifi_controller webserver display hccapx_serializer pcap_serializer wsl_bypasser debug_log spiffs fatfs vfs esp_partition nvs_flash)
