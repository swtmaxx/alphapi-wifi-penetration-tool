idf_component_register(
    SRCS "wsl_bypasser.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_event esp_wifi
)
# Same-name override of the Wi-Fi stack sanity check. This mirrors the upstream
# ESP32-S2 build (which transmits successfully) rather than -Wl,--wrap.
target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)