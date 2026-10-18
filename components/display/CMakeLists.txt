idf_component_register(SRCS "display.c"
                    INCLUDE_DIRS "include"
                    /* ESP-IDF 6.x no longer re-exports the SPI/GPIO drivers from
                       the "driver" component, so depend on them explicitly. */
                    PRIV_REQUIRES esp_driver_spi esp_driver_gpio)
