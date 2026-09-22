/**
 * @file display.h
 * @brief ST7789 SPI display driver for AlphaPi One S v1.7
 */
#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Drawing area is 160x128 landscape (rotation=1). */
#define DISPLAY_WIDTH  160
#define DISPLAY_HEIGHT 128

/* RGB565 palette */
#define COLOR_BLACK   0x0000
#define COLOR_WHITE   0xFFFF
#define COLOR_RED     0xF800
#define COLOR_GREEN   0x07E0
#define COLOR_BLUE    0x001F
#define COLOR_YELLOW  0xFFE0
#define COLOR_CYAN    0x07FF
#define COLOR_MAGENTA 0xF81F
#define COLOR_ORANGE  0xFD20
#define COLOR_GRAY    0x8410
#define COLOR_DARKGRAY 0x2104

/**
 * @brief Initialise SPI bus, GPIOs and the ST7789 controller.
 *
 * Must be called once before any drawing call.
 */
void display_init(void);

/**
 * @brief Turn the backlight on or off.
 */
void display_backlight(bool on);

/**
 * @brief Fill the whole screen with a solid colour.
 */
void display_fill(uint16_t color);

/**
 * @brief Fill a rectangle with a solid colour.
 */
void display_fill_rect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t color);

/**
 * @brief Draw a single 5x7 glyph.
 */
void display_draw_char(int16_t x, int16_t y, char ch, uint16_t fg, uint16_t bg);

/**
 * @brief Draw a string with the 5x7 font.
 */
void display_draw_text(int16_t x, int16_t y, const char *s, uint16_t fg, uint16_t bg);

/**
 * @brief Draw UTF-8 text using the built-in ASCII and Chinese glyphs.
 */
void display_draw_text_utf8(int16_t x, int16_t y, const char *s, uint16_t fg, uint16_t bg);

/**
 * @brief Draw a string scaled by an integer factor (1 = native 5x7).
 */
void display_draw_text_scaled(int16_t x, int16_t y, const char *s, uint16_t fg, uint16_t bg, uint8_t scale);

/**
 * @brief Pixel width of a string rendered at the given scale.
 */
int16_t display_text_width(const char *s, uint8_t scale);

/**
 * @brief Push the framebuffer to the display.
 *
 * Call once after a batch of drawing calls.
 */
void display_flush(void);

#endif /* DISPLAY_H */
