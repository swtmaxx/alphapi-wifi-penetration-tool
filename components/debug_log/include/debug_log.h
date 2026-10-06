/**
 * @file debug_log.h
 * @brief Keeps a small in-memory copy of ESP-IDF log output.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

#include <stddef.h>

/** Maximum response size accepted by debug_log_read(). */
#define DEBUG_LOG_EXPORT_MAX 16384

/** Start capturing logs while preserving the normal ESP-IDF output. */
void debug_log_init(void);

/** Copy the oldest available log lines into buffer and return the byte count. */
size_t debug_log_read(char *buffer, size_t capacity);

/** Remove all lines currently stored in the ring buffer. */
void debug_log_clear(void);

#endif
