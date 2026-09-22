idf_component_register(
    SRCS "wsl_bypasser.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_event esp_wifi
)
# Redirect the Wi-Fi library's frame sanity check to __wrap_... in wsl_bypasser.c.
# --wrap does not depend on link order, unlike -zmuldefs.
target_link_libraries(${COMPONENT_LIB} -Wl,--wrap=ieee80211_raw_frame_sanity_check)