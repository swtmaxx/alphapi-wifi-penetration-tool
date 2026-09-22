/**
 * @file display.c
 * @brief ST7789 SPI display driver for AlphaPi One S v1.7.
 *
 * Uses a RAM framebuffer; display_flush() pushes it out over SPI in one DMA
 * transaction so the render task never blocks on thousands of bus writes.
 *
 * Pin map was extracted from the factory MicroPython firmware (hal.gpio_map).
 */
#include "display.h"
#include "font5x7.h"
#include "font_cjk.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_rom_sys.h"
#include "esp_attr.h"

/* AlphaPi One S v1.7 pin map (hal.gpio_map) */
#define TFT_SCK   37
#define TFT_MOSI  38
#define TFT_MISO  45
#define TFT_CS    34
#define TFT_DC    36
#define TFT_RST   35
#define TFT_BL    33

#define TFT_SPI_HOST   SPI3_HOST
#define SPI_FREQ_HZ    (31 * 1000 * 1000)
#define FRAMEBUF_PIXEL (DISPLAY_WIDTH * DISPLAY_HEIGHT)
#define FRAMEBUF_BYTES (FRAMEBUF_PIXEL * 2)

/* ST7789 commands */
#define ST7789_SWRESET 0x01
#define ST7789_SLPOUT  0x11
#define ST7789_COLMOD  0x3A
#define ST7789_MADCTL  0x36
#define ST7789_CASET   0x2A
#define ST7789_RASET   0x2B
#define ST7789_RAMWR   0x2C
#define ST7789_INVON   0x21
#define ST7789_INVOFF  0x20
#define ST7789_NORON   0x13
#define ST7789_DISPON  0x29

/* rotation=1 -> landscape, MX|MV */
#define ST7789_MADCTL_ROTATION 0x60

static spi_device_handle_t spi_handle;
static bool display_ready;

/* DMA buffers must be 4-byte aligned and in internal RAM */
static DMA_ATTR uint16_t framebuffer[FRAMEBUF_PIXEL];

static void st7789_send_cmd(uint8_t cmd)
{
    spi_transaction_t t = {
        .length = 8,
        .flags = SPI_TRANS_USE_TXDATA,
    };
    t.tx_data[0] = cmd;
    gpio_set_level(TFT_CS, 0);
    gpio_set_level(TFT_DC, 0);
    spi_device_polling_transmit(spi_handle, &t);
    gpio_set_level(TFT_CS, 1);
}

static void st7789_send_data_dma(const uint8_t *data, size_t len)
{
    spi_transaction_t t = {
        .length = len * 8,
        .tx_buffer = data,
        .flags = 0,
    };
    gpio_set_level(TFT_CS, 0);
    gpio_set_level(TFT_DC, 1);
    spi_device_transmit(spi_handle, &t);
    gpio_set_level(TFT_CS, 1);
}

static void st7789_send_byte(uint8_t value)
{
    spi_transaction_t t = {
        .length = 8,
        .flags = SPI_TRANS_USE_TXDATA,
    };
    t.tx_data[0] = value;
    gpio_set_level(TFT_CS, 0);
    gpio_set_level(TFT_DC, 1);
    spi_device_polling_transmit(spi_handle, &t);
    gpio_set_level(TFT_CS, 1);
}

static void st7789_hw_reset(void)
{
    gpio_set_level(TFT_RST, 0);
    esp_rom_delay_us(20000);
    gpio_set_level(TFT_RST, 1);
    esp_rom_delay_us(150000);
}

static void st7789_set_window(int16_t x0, int16_t y0, int16_t x1, int16_t y1)
{
    st7789_send_cmd(ST7789_CASET);
    st7789_send_byte((uint8_t)(x0 >> 8));
    st7789_send_byte((uint8_t)(x0 & 0xFF));
    st7789_send_byte((uint8_t)(x1 >> 8));
    st7789_send_byte((uint8_t)(x1 & 0xFF));

    st7789_send_cmd(ST7789_RASET);
    st7789_send_byte((uint8_t)(y0 >> 8));
    st7789_send_byte((uint8_t)(y0 & 0xFF));
    st7789_send_byte((uint8_t)(y1 >> 8));
    st7789_send_byte((uint8_t)(y1 & 0xFF));

    st7789_send_cmd(ST7789_RAMWR);
}

static void st7789_init_sequence(void)
{
    st7789_send_cmd(ST7789_SWRESET);
    esp_rom_delay_us(150000);
    st7789_send_cmd(ST7789_SLPOUT);
    esp_rom_delay_us(120000);

    st7789_send_cmd(ST7789_COLMOD);
    st7789_send_byte(0x55);
    esp_rom_delay_us(10000);

    st7789_send_cmd(ST7789_MADCTL);
    st7789_send_byte(ST7789_MADCTL_ROTATION);

    st7789_send_cmd(ST7789_INVOFF);

    st7789_send_cmd(ST7789_NORON);
    esp_rom_delay_us(10000);
    st7789_send_cmd(ST7789_DISPON);
    esp_rom_delay_us(100000);
}

void display_init(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << TFT_CS) | (1ULL << TFT_DC) | (1ULL << TFT_RST) | (1ULL << TFT_BL),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);

    gpio_set_level(TFT_CS, 1);
    gpio_set_level(TFT_DC, 0);
    gpio_set_level(TFT_BL, 0);
    /* turn the backlight on early so a failed SPI init is still visible */
    gpio_set_level(TFT_BL, 1);


    spi_bus_config_t buscfg = {
        .mosi_io_num = TFT_MOSI,
        .miso_io_num = TFT_MISO,
        .sclk_io_num = TFT_SCK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = FRAMEBUF_BYTES + 8,
    };
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = SPI_FREQ_HZ,
        .mode = 0,
        .spics_io_num = -1,
        .queue_size = 2,
    };

    esp_err_t err = spi_bus_initialize(TFT_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        /* MicroPython used SPI(2) which maps to SPI3_HOST; fall back to SPI2_HOST */
        err = spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO);
        if (err != ESP_OK) {
            return;
        }
        err = spi_bus_add_device(SPI2_HOST, &devcfg, &spi_handle);
        if (err != ESP_OK) {
            spi_bus_free(SPI2_HOST);
            return;
        }
        goto spi_ready;
    }
    err = spi_bus_add_device(TFT_SPI_HOST, &devcfg, &spi_handle);
    if (err != ESP_OK) {
        spi_bus_free(TFT_SPI_HOST);
        return;
    }

spi_ready:
    st7789_hw_reset();
    st7789_init_sequence();

    display_ready = true;
    display_fill(COLOR_BLACK);
    display_flush();
    display_backlight(true);
}

void display_backlight(bool on)
{
    gpio_set_level(TFT_BL, on ? 1 : 0);
}

void display_fill(uint16_t color)
{
    if (!display_ready) return;
    for (int i = 0; i < FRAMEBUF_PIXEL; i++) framebuffer[i] = color;
}

void display_fill_rect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color)
{
    if (!display_ready) return;
    if (w <= 0 || h <= 0) return;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > DISPLAY_WIDTH)  w = DISPLAY_WIDTH - x;
    if (y + h > DISPLAY_HEIGHT) h = DISPLAY_HEIGHT - y;
    if (w <= 0 || h <= 0) return;

    for (int16_t row = 0; row < h; row++) {
        uint16_t *line = &framebuffer[(y + row) * DISPLAY_WIDTH + x];
        for (int16_t col = 0; col < w; col++) line[col] = color;
    }
}

void display_draw_char(int16_t x, int16_t y, char ch, uint16_t fg, uint16_t bg)
{
    if (!display_ready) return;
    if (ch < 0x20 || ch >= 0x7F) ch = ' ';

    const uint8_t *glyph = font5x7[ch - 0x20];
    for (int8_t col = 0; col < FONT5X7_WIDTH; col++) {
        uint8_t bits = glyph[col];
        for (int8_t row = 0; row < FONT5X7_HEIGHT; row++) {
            int16_t px = x + col, py = y + row;
            if (px < 0 || px >= DISPLAY_WIDTH || py < 0 || py >= DISPLAY_HEIGHT) continue;
            framebuffer[py * DISPLAY_WIDTH + px] = (bits & (1 << row)) ? fg : bg;
        }
    }
}

void display_draw_text_scaled(int16_t x, int16_t y, const char *s, uint16_t fg, uint16_t bg, uint8_t scale)
{
    if (!display_ready || scale == 0) return;
    if (scale == 1) {
        display_draw_text(x, y, s, fg, bg);
        return;
    }

    while (*s) {
        char ch = *s++;
        if (ch < 0x20 || ch >= 0x7F) ch = ' ';
        const uint8_t *glyph = font5x7[ch - 0x20];
        for (int8_t col = 0; col < FONT5X7_WIDTH; col++) {
            uint8_t bits = glyph[col];
            for (int8_t row = 0; row < FONT5X7_HEIGHT; row++) {
                uint16_t c = (bits & (1 << row)) ? fg : bg;
                int16_t px = x + col * scale;
                int16_t py = y + row * scale;
                for (int16_t sy = 0; sy < scale; sy++) {
                    for (int16_t sx = 0; sx < scale; sx++) {
                        int16_t fx = px + sx, fy = py + sy;
                        if (fx < 0 || fx >= DISPLAY_WIDTH || fy < 0 || fy >= DISPLAY_HEIGHT) continue;
                        framebuffer[fy * DISPLAY_WIDTH + fx] = c;
                    }
                }
            }
        }
        x += (FONT5X7_WIDTH + 1) * scale;
    }
}

void display_draw_text(int16_t x, int16_t y, const char *s, uint16_t fg, uint16_t bg)
{
    if (!display_ready) return;
    while (*s) {
        display_draw_char(x, y, *s++, fg, bg);
        x += FONT5X7_WIDTH + 1;
    }
}

static const char *decode_utf8(const char *s, uint32_t *codepoint)
{
    const uint8_t *p = (const uint8_t *)s;
    if (p[0] < 0x80) {
        *codepoint = p[0];
        return s + 1;
    }
    if ((p[0] & 0xE0) == 0xC0 && p[1] != 0) {
        *codepoint = ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F);
        return s + 2;
    }
    if ((p[0] & 0xF0) == 0xE0 && p[1] != 0 && p[2] != 0) {
        *codepoint = ((uint32_t)(p[0] & 0x0F) << 12) |
                     ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        return s + 3;
    }
    if ((p[0] & 0xF8) == 0xF0 && p[1] != 0 && p[2] != 0 && p[3] != 0) {
        *codepoint = ((uint32_t)(p[0] & 0x07) << 18) |
                     ((uint32_t)(p[1] & 0x3F) << 12) |
                     ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        return s + 4;
    }
    *codepoint = '?';
    return s + 1;
}

void display_draw_text_utf8(int16_t x, int16_t y, const char *s, uint16_t fg, uint16_t bg)
{
    if (!display_ready || s == NULL) return;

    while (*s && x < DISPLAY_WIDTH) {
        uint32_t codepoint;
        s = decode_utf8(s, &codepoint);
        if (codepoint < 0x80) {
            display_draw_char(x, y, (char)codepoint, fg, bg);
            x += FONT5X7_WIDTH + 1;
            continue;
        }

        const font_cjk_glyph_t *glyph = font_cjk_find(codepoint);
        if (glyph == NULL) {
            display_draw_char(x, y, '?', fg, bg);
            x += FONT5X7_WIDTH + 1;
            continue;
        }
        display_fill_rect(x, y, 16, 16, bg);
        for (int row = 0; row < 16; row++) {
            for (int col = 0; col < 16; col++) {
                if (glyph->rows[row] & (1U << col)) {
                    int16_t px = x + col;
                    int16_t py = y + row;
                    if (px >= 0 && px < DISPLAY_WIDTH && py >= 0 && py < DISPLAY_HEIGHT) {
                        framebuffer[py * DISPLAY_WIDTH + px] = fg;
                    }
                }
            }
        }
        x += 16;
    }
}

int16_t display_text_width(const char *s, uint8_t scale)
{
    if (scale == 0) scale = 1;
    int16_t len = 0;
    while (*s++) len++;
    if (len == 0) return 0;
    return len * (FONT5X7_WIDTH + 1) * scale - scale;
}

void display_flush(void)
{
    if (!display_ready) return;

    /* byte-swap RGB565 in place for the SPI wire format; the next render
       overwrites the framebuffer anyway */
    uint8_t *bytes = (uint8_t *)framebuffer;
    for (int i = 0; i < FRAMEBUF_PIXEL; i++) {
        uint8_t tmp = bytes[i * 2];
        bytes[i * 2] = bytes[i * 2 + 1];
        bytes[i * 2 + 1] = tmp;
    }

    st7789_set_window(0, 0, DISPLAY_WIDTH - 1, DISPLAY_HEIGHT - 1);
    st7789_send_data_dma(bytes, FRAMEBUF_BYTES);
}
