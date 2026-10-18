# ESP-IDF 6.x no longer re-exports the SPI/GPIO drivers from the "driver"
# component (driver/include/driver/spi_master.h is gone), so depend on them
# explicitly.
idf_component_register(SRCS "display.c"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES esp_driver_spi esp_driver_gpio)
