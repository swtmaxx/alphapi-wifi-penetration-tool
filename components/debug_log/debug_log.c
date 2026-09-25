/**
 * @file debug_log.c
 * @brief In-memory ESP-IDF log ring buffer for devices without a console.
 */
#include "debug_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

#define DEBUG_LOG_LINE_COUNT 96
#define DEBUG_LOG_LINE_MAX   192

static char log_lines[DEBUG_LOG_LINE_COUNT][DEBUG_LOG_LINE_MAX];
static size_t log_write_index;
static size_t log_line_count;
static portMUX_TYPE log_mux = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t previous_vprintf;

static int debug_log_vprintf(const char *format, va_list args)
{
    char line[DEBUG_LOG_LINE_MAX];
    va_list capture_args;
    va_copy(capture_args, args);
    int written = vsnprintf(line, sizeof(line), format, capture_args);
    va_end(capture_args);

    if (written >= 0) {
        size_t length = (size_t)written;
        if (length >= sizeof(line)) length = sizeof(line) - 1;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            length--;
        }
        line[length] = '\0';

        if (length > 0) {
            portENTER_CRITICAL(&log_mux);
            memcpy(log_lines[log_write_index], line, length + 1);
            log_write_index = (log_write_index + 1) % DEBUG_LOG_LINE_COUNT;
            if (log_line_count < DEBUG_LOG_LINE_COUNT) log_line_count++;
            portEXIT_CRITICAL(&log_mux);
        }
    }

    /* Keep the normal UART/USB output path working as before. */
    return previous_vprintf != NULL ? previous_vprintf(format, args) : written;
}

void debug_log_init(void)
{
    portENTER_CRITICAL(&log_mux);
    log_write_index = 0;
    log_line_count = 0;
    portEXIT_CRITICAL(&log_mux);
    previous_vprintf = esp_log_set_vprintf(debug_log_vprintf);
}

size_t debug_log_read(char *buffer, size_t capacity)
{
    if (buffer == NULL || capacity == 0) return 0;

    portENTER_CRITICAL(&log_mux);
    size_t used = 0;
    size_t first = (log_write_index + DEBUG_LOG_LINE_COUNT - log_line_count) %
                   DEBUG_LOG_LINE_COUNT;
    for (size_t i = 0; i < log_line_count; i++) {
        const char *line = log_lines[(first + i) % DEBUG_LOG_LINE_COUNT];
        size_t length = strnlen(line, DEBUG_LOG_LINE_MAX);
        if (used >= capacity - 1 || length > capacity - used - 1) break;
        memcpy(buffer + used, line, length);
        used += length;
        buffer[used++] = '\n';
    }
    buffer[used] = '\0';
    portEXIT_CRITICAL(&log_mux);
    return used;
}

void debug_log_clear(void)
{
    portENTER_CRITICAL(&log_mux);
    log_write_index = 0;
    log_line_count = 0;
    portEXIT_CRITICAL(&log_mux);
}
