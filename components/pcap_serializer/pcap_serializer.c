/**
 * @file pcap_serializer.c
 * @brief PCAP serializer that streams captured frames to LittleFS on Flash.
 *
 * Frames are accumulated in a small RAM write buffer and flushed to the
 * capture file whenever it fills, so the WiFi callback never blocks on a
 * Flash write for every single frame.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#include "pcap_serializer.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "esp_littlefs.h"
/* CONFIG_LITTLEFS_OBJ_NAME_LEN: the file-name budget depends on it. */
#include "sdkconfig.h"
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>

static const char *TAG = "pcap_serializer";

#define SNAPLEN 65535
#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#define LINKTYPE_IEEE802_11 105

#define PCAP_BASE_PATH   "/pcap"
#define PCAP_FILE_PATH   PCAP_BASE_PATH "/capture.pcap"
#define PCAP_FILE_PATH_FMT PCAP_BASE_PATH "/capture_%03u.pcap"
/* Untagged result name, e.g. pmkid_007.txt. */
#define PCAP_FILE_PATH_TEXT_FMT PCAP_BASE_PATH "/%s_%03u.txt"
/* Indexed name with an SSID tag, e.g. capture_007_MyWiFi.pcap. The separator
 * before the tag is required: without it an SSID such as "504" would yield
 * "capture_001504.pcap", which the index parser reads as 1504. */
#define PCAP_FILE_PATH_TAGGED_FMT PCAP_BASE_PATH "/%s_%03u_%s%s"
#define PCAP_SSID_TAG_MAX 24
/* LittleFS keeps the object name (basename) in a buffer of
 * CONFIG_LITTLEFS_OBJ_NAME_LEN bytes, so a name may use one character less:
 * "Maximum object name length including NULL terminator." The default is 64,
 * i.e. 63 usable characters (SPIFFS used to allow only 31). */
#ifndef CONFIG_LITTLEFS_OBJ_NAME_LEN
#define CONFIG_LITTLEFS_OBJ_NAME_LEN 64
#endif
#define PCAP_FS_NAME_MAX ((unsigned) CONFIG_LITTLEFS_OBJ_NAME_LEN - 1)
#define PCAP_DIR_PATH    PCAP_BASE_PATH
#define WRITE_BUF_SIZE   2048

static unsigned pcap_size = 0;
static unsigned pcap_frames = 0;
static FILE *pcap_file = NULL;
static char pcap_cur_path[96] = PCAP_FILE_PATH;
static unsigned pcap_file_index = 1;
static char pcap_ssid_tag[PCAP_SSID_TAG_MAX + 1] = "";
static uint8_t write_buf[WRITE_BUF_SIZE];
static unsigned write_buf_used = 0;
static bool storage_mounted = false;
static pcap_storage_state_t storage_state = PCAP_STORAGE_MOUNT_ERROR;
static SemaphoreHandle_t pcap_mutex = NULL;

static bool ensure_mutex(void)
{
    if (pcap_mutex == NULL) pcap_mutex = xSemaphoreCreateMutex();
    return pcap_mutex != NULL;
}

static void lock_serializer(void)
{
    xSemaphoreTake(pcap_mutex, portMAX_DELAY);
}

static void unlock_serializer(void)
{
    xSemaphoreGive(pcap_mutex);
}

/**
 * @brief Whether the capture partition still looks untouched (all 0xFF).
 *
 * Only such a partition is safe to format. A partition that fails to mount but
 * still holds bytes may contain captures the user has not downloaded yet, and
 * formatting it would destroy that evidence, so it is reported as a mount
 * error instead.
 */
static bool partition_is_blank(void)
{
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_LITTLEFS, NULL);
    if (part == NULL) return false;

    uint8_t probe[256];
    size_t checked = 0;
    /* SPIFFS writes its own structures at the start of the partition, so a
       small probe tells a blank partition apart from a corrupt one. */
    while (checked < part->size && checked < 4096) {
        if (esp_partition_read(part, checked, probe, sizeof(probe)) != ESP_OK) {
            return false;
        }
        for (size_t i = 0; i < sizeof(probe); i++) {
            if (probe[i] != 0xFF) return false;
        }
        checked += sizeof(probe);
    }
    return true;
}

static bool mount_storage(void)
{
    if (storage_mounted) return true;

    esp_vfs_littlefs_conf_t conf = {
        .base_path = PCAP_BASE_PATH,
        .partition_label = NULL,
        /* Do not format on a plain mount failure: that would silently wipe
         * captures that may still be needed. */
        .format_if_mount_failed = false,
        .read_only = false,
        .dont_mount = false,
        /* Let a freshly formatted filesystem grow to the whole partition. */
        .grow_on_mount = true,
    };
    esp_err_t ret = esp_vfs_littlefs_register(&conf);
    if (ret != ESP_OK) {
        /* A freshly flashed device has an untouched (all-0xFF) partition. It
           holds nothing, so formatting it makes capturing work out of the box
           without ever risking stored captures. */
        if (partition_is_blank()) {
            ESP_LOGW(TAG, "Capture partition is blank; formatting it for first use");
            (void) esp_vfs_littlefs_unregister(NULL);
            conf.format_if_mount_failed = true;
            ret = esp_vfs_littlefs_register(&conf);
        }
    }
    if (ret != ESP_OK) {
        storage_state = PCAP_STORAGE_MOUNT_ERROR;
        ESP_LOGE(TAG, "Failed to mount LittleFS (%s); existing captures were left untouched. "
                      "If this device was upgraded from the SPIFFS build, format the storage "
                      "partition once (POST /storage-format).",
                 esp_err_to_name(ret));
        return false;
    }
    storage_mounted = true;
    storage_state = PCAP_STORAGE_OK;
    return true;
}

static void set_write_error(void)
{
    storage_state = (errno == ENOSPC) ? PCAP_STORAGE_FULL : PCAP_STORAGE_IO_ERROR;
}

static bool flush_write_buf(void)
{
    if (pcap_file == NULL || write_buf_used == 0) return true;
    size_t written = fwrite(write_buf, 1, write_buf_used, pcap_file);
    if (written != write_buf_used) {
        set_write_error();
        ESP_LOGE(TAG, "Failed to write PCAP buffer (%u/%u bytes)",
                 (unsigned) written, write_buf_used);
        /* Keep only the bytes that did not reach the file, otherwise a retry in
           pcap_serializer_deinit() would append them a second time and corrupt
           the record stream. */
        if (written > 0 && written < write_buf_used) {
            memmove(write_buf, write_buf + written, write_buf_used - written);
            write_buf_used -= (unsigned) written;
        }
        return false;
    }
    write_buf_used = 0;
    if (fflush(pcap_file) != 0) {
        set_write_error();
        ESP_LOGE(TAG, "Failed to flush PCAP file");
        return false;
    }
    /* SPIFFS wrote the data on fflush(); LittleFS only does so on fsync(). Ask
       explicitly so a power cut cannot lose a capture on either backend. */
    if (fsync(fileno(pcap_file)) != 0 && errno != EINVAL && errno != ENOSYS) {
        set_write_error();
        ESP_LOGE(TAG, "Failed to sync PCAP file");
        return false;
    }
    return true;
}

static bool append_bytes(const uint8_t *data, unsigned size)
{
    while (size > 0) {
        if (storage_state != PCAP_STORAGE_OK || pcap_file == NULL) return false;
        unsigned space = WRITE_BUF_SIZE - write_buf_used;
        unsigned copy = size > space ? space : size;
        memcpy(&write_buf[write_buf_used], data, copy);
        write_buf_used += copy;
        data += copy;
        size -= copy;
        if (write_buf_used == WRITE_BUF_SIZE && !flush_write_buf()) return false;
    }
    return true;
}

/**
 * @brief Build a filesystem-safe tag from an SSID.
 *
 * Keeps ASCII letters, digits, hyphen and underscore; every other byte
 * (including UTF-8 continuation bytes) becomes '_' so the name stays valid
 * on FAT/SPIFFS and remains readable in a download list.
 */
static void build_ssid_tag(const uint8_t *ssid, unsigned len)
{
    unsigned out = 0;
    if (ssid != NULL) {
        for (unsigned i = 0; i < len && out < PCAP_SSID_TAG_MAX; i++) {
            uint8_t c = ssid[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_') {
                pcap_ssid_tag[out++] = (char) c;
            } else if (c >= 0x80 || c == ' ') {
                /* Collapse runs of non-ASCII/space into a single '_'. */
                if (out > 0 && pcap_ssid_tag[out - 1] != '_') {
                    pcap_ssid_tag[out++] = '_';
                }
            }
        }
        /* Trim a trailing separator left by the collapse rule. */
        while (out > 0 && pcap_ssid_tag[out - 1] == '_') out--;
    }
    pcap_ssid_tag[out] = '\0';
}

/**
 * @brief Build a tagged file name that SPIFFS will actually accept.
 *
 * The SSID tag is shortened until the resulting basename fits the SPIFFS object
 * name limit. Without this a long SSID (a very common case) makes fopen() fail
 * with ENAMETOOLONG, which turned the whole capture into a storage error.
 *
 * @param prefix    name prefix without the trailing separator, e.g. "capture"
 * @param extension file extension including the dot, e.g. ".pcap"
 * @param index     capture index, written as three digits
 * @param reserve   characters appended to the name later (".tmp" = 4) so that
 *                  the temporary file used by the atomic text write also fits
 */
static void build_tagged_name(char *out, size_t out_size, const char *prefix,
                              const char *extension, unsigned index,
                              unsigned reserve)
{
    for (;;) {
        int written = snprintf(out, out_size, PCAP_FILE_PATH_TAGGED_FMT,
                               prefix, index, pcap_ssid_tag, extension);
        if (written < 0 || (size_t) written >= out_size) {
            out[0] = '\0';
            return;
        }

        /* SPIFFS limits the object name, not the whole path. */
        const char *base = strrchr(out, '/');
        size_t name_len = strlen(base != NULL ? base + 1 : out);
        if (name_len + reserve <= PCAP_FS_NAME_MAX) return;

        size_t tag_len = strlen(pcap_ssid_tag);
        if (tag_len == 0) {
            ESP_LOGE(TAG, "Generated name exceeds the SPIFFS limit: %s", out);
            return;
        }
        pcap_ssid_tag[tag_len - 1] = '\0';
    }
}

/**
 * @brief Join the capture directory with a file name, rejecting overlong input.
 *
 * @return true when the joined path fits in out.
 */
static bool build_full_path(char *out, size_t out_size, const char *name)
{
    static const char prefix[] = PCAP_BASE_PATH "/";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t name_len = strlen(name);
    if (prefix_len + name_len + 1 > out_size) return false;
    memcpy(out, prefix, prefix_len);
    memcpy(out + prefix_len, name, name_len + 1);
    return true;
}

/**
 * @brief Parse "<prefix><digits>" and require the digits to end at '.' or '_'.
 *
 * A naive sscanf("<prefix>%u") is greedy: with a tagged name such as
 * "capture_001_1001_WiFi5.pcap" it swallows "0011001" as the index, so every
 * later capture gets a bogus, ever-growing number. Requiring an explicit
 * separator after the digits keeps indexed names and legacy names apart.
 *
 * @param name   directory entry name, e.g. "capture_007_MyWiFi.pcap"
 * @param prefix expected literal prefix, e.g. "capture_"
 * @param out_index parsed index on success
 * @return true when name matches the "<prefix><digits>(.|_)" shape
 */
static bool parse_indexed_name(const char *name, const char *prefix, unsigned *out_index)
{
    size_t prefix_len = strlen(prefix);
    if (strncmp(name, prefix, prefix_len) != 0) return false;

    const char *p = name + prefix_len;
    if (*p < '0' || *p > '9') return false;

    unsigned value = 0;
    unsigned digits = 0;
    while (*p >= '0' && *p <= '9') {
        /* Anything this long is a corrupted legacy name, not a real index. */
        if (digits >= 6) return false;
        value = value * 10u + (unsigned) (*p - '0');
        p++;
        digits++;
    }
    if (digits == 0) return false;
    /* The index must be followed by the extension dot or the SSID-tag separator. */
    if (*p != '.' && *p != '_') return false;

    *out_index = value;
    return true;
}

static bool has_extension(const char *name, const char *extension)
{
    const char *dot = strrchr(name, '.');
    return dot != NULL && strcmp(dot, extension) == 0;
}

/**
 * @brief Whether a stored name only uses the characters we generate.
 *
 * Names are echoed back in the Content-Disposition header, so anything else
 * (quotes, CR/LF, control bytes) must never be treated as a stored file.
 */
static bool has_safe_name_chars(const char *name)
{
    for (const char *p = name; *p != '\0'; p++) {
        char c = *p;
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

static bool is_pcap_name(const char *name)
{
    if (!has_safe_name_chars(name)) return false;
    if (strcmp(name, "capture.pcap") == 0) return true;
    unsigned index = 0;
    return parse_indexed_name(name, "capture_", &index) &&
           has_extension(name, ".pcap");
}

static bool is_result_name(const char *name)
{
    if (!has_safe_name_chars(name)) return false;
    unsigned index = 0;
    return parse_indexed_name(name, "pmkid_", &index) &&
           has_extension(name, ".txt");
}

static bool is_stored_file_name(const char *name)
{
    return is_pcap_name(name) || is_result_name(name);
}

static void pick_next_capture_path(void)
{
    DIR *dir = opendir(PCAP_DIR_PATH);
    unsigned max_index = 0;
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            unsigned idx = 0;
            /* Accept both capture_NNN.pcap and capture_NNN_tag.pcap. */
            if (is_pcap_name(ent->d_name) &&
                parse_indexed_name(ent->d_name, "capture_", &idx) &&
                idx > max_index) {
                max_index = idx;
            }
        }
        closedir(dir);
    }
    pcap_file_index = max_index + 1;

    if (pcap_ssid_tag[0] != '\0') {
        build_tagged_name(pcap_cur_path, sizeof(pcap_cur_path),
                          "capture", ".pcap", pcap_file_index, 0);
    } else {
        snprintf(pcap_cur_path, sizeof(pcap_cur_path),
                 PCAP_FILE_PATH_FMT, pcap_file_index);
    }
}

/**
 * @brief Erases and re-creates the capture filesystem.
 *
 * Needed once when the storage backend changed (a SPIFFS partition cannot be
 * mounted as LittleFS). Destroys every stored capture, so it is only reachable
 * through an explicit request.
 */
bool pcap_serializer_format_storage(void)
{
    if (!ensure_mutex()) return false;

    lock_serializer();
    if (pcap_file != NULL) {
        fclose(pcap_file);
        pcap_file = NULL;
    }
    write_buf_used = 0;
    (void) esp_vfs_littlefs_unregister(NULL);
    storage_mounted = false;

    esp_err_t err = esp_littlefs_format(NULL);
    bool ok = (err == ESP_OK);
    if (!ok) {
        ESP_LOGE(TAG, "Failed to format the capture partition: %s", esp_err_to_name(err));
        storage_state = PCAP_STORAGE_IO_ERROR;
    } else {
        ok = mount_storage();
    }
    unlock_serializer();
    return ok;
}

bool pcap_serializer_early_init(void)
{
    return ensure_mutex();
}

bool pcap_serializer_init(const uint8_t *ssid, unsigned ssid_len)
{
    build_ssid_tag(ssid, ssid_len);

    if (!ensure_mutex()) return false;
    lock_serializer();

    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    if (pcap_file != NULL) {
        bool previous_ok = flush_write_buf();
        if (fclose(pcap_file) != 0) {
            set_write_error();
            previous_ok = false;
        }
        pcap_file = NULL;
        write_buf_used = 0;
        if (!previous_ok) {
            unlock_serializer();
            return false;
        }
    }

    mkdir(PCAP_DIR_PATH, 0777);
    pick_next_capture_path();

    pcap_file = fopen(pcap_cur_path, "w+b");
    if (pcap_file == NULL) {
        set_write_error();
        ESP_LOGE(TAG, "Failed to open %s", pcap_cur_path);
        unlock_serializer();
        return false;
    }

    pcap_global_header_t pcap_global_header = {
        .magic_number = PCAP_MAGIC_NUMBER,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = SNAPLEN,
        .network = LINKTYPE_IEEE802_11
    };

    write_buf_used = 0;
    pcap_size = 0;
    pcap_frames = 0;
    storage_state = PCAP_STORAGE_OK;
    if (!append_bytes((uint8_t *)&pcap_global_header, sizeof(pcap_global_header_t)) ||
        !flush_write_buf()) {
        fclose(pcap_file);
        pcap_file = NULL;
        write_buf_used = 0;
        unlock_serializer();
        return false;
    }
    pcap_size = sizeof(pcap_global_header_t);
    unlock_serializer();
    return true;
}

bool pcap_serializer_append_frame(const uint8_t *buffer, unsigned size, unsigned ts_usec)
{
    if (size == 0) return true;
    if (buffer == NULL || !ensure_mutex()) return false;

    lock_serializer();
    if (pcap_file == NULL) {
        unlock_serializer();
        return false;
    }

    if (storage_state != PCAP_STORAGE_OK) {
        unlock_serializer();
        return false;
    }

    if (size > SNAPLEN) size = SNAPLEN;

    pcap_record_header_t pcap_record_header = {
        .ts_sec = ts_usec / 1000000,
        .ts_usec = ts_usec % 1000000,
        .incl_len = size,
        .orig_len = size,
    };

    bool ok = append_bytes((uint8_t *)&pcap_record_header, sizeof(pcap_record_header_t)) &&
              append_bytes(buffer, size);
    if (!ok) {
        unlock_serializer();
        return false;
    }
    pcap_size += sizeof(pcap_record_header_t) + size;
    pcap_frames++;
    unlock_serializer();
    return true;
}

bool pcap_serializer_deinit(void)
{
    if (!ensure_mutex()) return false;
    lock_serializer();
    bool ok = flush_write_buf();
    if (pcap_file != NULL) {
        if (fclose(pcap_file) != 0) {
            set_write_error();
            ok = false;
        }
        pcap_file = NULL;
    }
    write_buf_used = 0;
    /* Keep the mounted partition and size available for a later download. */
    unlock_serializer();
    return ok;
}

unsigned pcap_serializer_get_size(void)
{
    if (!ensure_mutex()) return 0;
    lock_serializer();
    unsigned size = pcap_size;
    unlock_serializer();
    return size;
}

unsigned pcap_serializer_get_frame_count(void)
{
    if (!ensure_mutex()) return 0;
    lock_serializer();
    unsigned frames = pcap_frames;
    unlock_serializer();
    return frames;
}

bool pcap_serializer_read(unsigned offset, uint8_t *buf, unsigned len)
{
    if ((buf == NULL && len != 0) || !ensure_mutex()) return false;

    lock_serializer();
    if (offset > pcap_size || len > pcap_size - offset) {
        unlock_serializer();
        return false;
    }
    if (len == 0) {
        unlock_serializer();
        return true;
    }

    bool ok = false;
    FILE *read_file = pcap_file;
    bool close_read_file = false;
    if (read_file == NULL) {
        read_file = fopen(pcap_cur_path, "rb");
        close_read_file = true;
    } else if (!flush_write_buf()) {
        unlock_serializer();
        return false;
    }

    if (read_file != NULL && fseek(read_file, offset, SEEK_SET) == 0) {
        ok = fread(buf, 1, len, read_file) == len;
    }
    if (close_read_file) {
        if (read_file != NULL) fclose(read_file);
    } else if (read_file != NULL) {
        /* Establish a write position before the next append. */
        fseek(read_file, 0, SEEK_END);
    }
    unlock_serializer();
    return ok;
}

static int compare_file_info(const void *a, const void *b)
{
    return strcmp(((const pcap_file_info_t *)a)->name, ((const pcap_file_info_t *)b)->name);
}

unsigned pcap_serializer_list(pcap_file_info_t *out, unsigned max)
{
    if (out == NULL || max == 0) return 0;
    if (!ensure_mutex()) return 0;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return 0;
    }

    unsigned count = 0;
    DIR *dir = opendir(PCAP_DIR_PATH);
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && count < max) {
            unsigned idx = 0;
            /* Accept capture_NNN.pcap and capture_NNN_tag.pcap only. */
            if (!is_pcap_name(ent->d_name) ||
                !parse_indexed_name(ent->d_name, "capture_", &idx)) continue;

            char full[96];
            if (!build_full_path(full, sizeof(full), ent->d_name)) continue;
            struct stat st;
            if (stat(full, &st) != 0) continue;

            strncpy(out[count].name, ent->d_name, sizeof(out[count].name) - 1);
            out[count].name[sizeof(out[count].name) - 1] = '\0';
            out[count].size = (unsigned)st.st_size;
            count++;
        }
        closedir(dir);
    }
    unlock_serializer();

    /* deterministic order: capture_001, capture_002, ... */
    if (count > 1) qsort(out, count, sizeof(pcap_file_info_t), compare_file_info);
    return count;
}

bool pcap_serializer_list_page(pcap_file_info_t *out, unsigned max,
                               unsigned offset, unsigned *total)
{
    if (out == NULL || max == 0 || total == NULL || !ensure_mutex()) return false;

    *total = 0;
    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    unsigned count = 0;
    DIR *dir = opendir(PCAP_DIR_PATH);
    if (dir == NULL) {
        unlock_serializer();
        return false;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (is_stored_file_name(ent->d_name)) count++;
    }
    closedir(dir);

    pcap_file_info_t *all = NULL;
    if (count > 0) {
        all = calloc(count, sizeof(*all));
        if (all == NULL) {
            unlock_serializer();
            return false;
        }
    }

    unsigned written = 0;
    dir = opendir(PCAP_DIR_PATH);
    if (dir == NULL) {
        free(all);
        unlock_serializer();
        return false;
    }
    while ((ent = readdir(dir)) != NULL && written < count) {
        if (!is_stored_file_name(ent->d_name)) continue;

        char full[96];
        struct stat st;
        if (!build_full_path(full, sizeof(full), ent->d_name) ||
            stat(full, &st) != 0 || st.st_size < 0) {
            /* A file can vanish between the counting pass and this pass (for
               example while delete-all runs): skip it rather than failing the
               whole listing. */
            continue;
        }
        strncpy(all[written].name, ent->d_name, sizeof(all[written].name) - 1);
        all[written].name[sizeof(all[written].name) - 1] = '\0';
        all[written].size = (unsigned) st.st_size;
        if (pcap_file != NULL && strcmp(full, pcap_cur_path) == 0) {
            all[written].size = pcap_size;
        }
        written++;
    }
    closedir(dir);

    if (written > 1) qsort(all, written, sizeof(*all), compare_file_info);
    unsigned page_count = 0;
    for (unsigned i = offset; i < written && page_count < max; i++) {
        out[page_count++] = all[i];
    }
    *total = written;
    free(all);
    unlock_serializer();
    return true;
}

bool pcap_serializer_read_file(const char *name, unsigned offset, uint8_t *buf, unsigned len)
{
    if (name == NULL || (buf == NULL && len != 0)) return false;
    if (strstr(name, "..") != NULL || strchr(name, '/') != NULL ||
        strchr(name, '\\') != NULL || !is_stored_file_name(name)) return false;
    if (!ensure_mutex()) return false;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    char full[96];
    if (!build_full_path(full, sizeof(full), name)) {
        unlock_serializer();
        return false;
    }

    if (pcap_file != NULL && strcmp(full, pcap_cur_path) == 0 &&
        !flush_write_buf()) {
        unlock_serializer();
        return false;
    }

    bool ok = false;
    struct stat st;
    if (stat(full, &st) == 0 && (unsigned)st.st_size >= offset &&
        len <= (unsigned)st.st_size - offset) {
        if (len == 0) {
            ok = true;
        } else {
            FILE *file = fopen(full, "rb");
            if (file != NULL) {
                if (fseek(file, offset, SEEK_SET) == 0) {
                    ok = fread(buf, 1, len, file) == len;
                }
                fclose(file);
            }
        }
    }
    unlock_serializer();
    return ok;
}
/**
 * @brief Pick the next "<prefix>_NNN[_tag].txt" path, scanning existing files.
 */
static void pick_next_text_path(const char *prefix, char *out, size_t out_size)
{
    DIR *dir = opendir(PCAP_DIR_PATH);
    unsigned max_index = 0;
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            unsigned idx = 0;
            char pattern[32];
            snprintf(pattern, sizeof(pattern), "%s_", prefix);
            if (parse_indexed_name(ent->d_name, pattern, &idx) &&
                idx > max_index) {
                max_index = idx;
            }
        }
        closedir(dir);
    }

    if (pcap_ssid_tag[0] != '\0') {
        /* Reserve 4 characters for the ".tmp" suffix used below. */
        build_tagged_name(out, out_size, prefix, ".txt", max_index + 1, 4);
    } else {
        snprintf(out, out_size, PCAP_FILE_PATH_TEXT_FMT,
                 prefix, max_index + 1);
    }
}

/**
 * @brief Delete one stored file from the capture directory.
 *
 * @param name file name as returned by pcap_serializer_list(), e.g. "capture_001.pcap"
 * @return true when the file no longer exists afterwards
 */
bool pcap_serializer_delete(const char *name)
{
    if (name == NULL || name[0] == '\0') return false;
    /* Refuse anything that could escape the capture directory. */
    if (strstr(name, "..") != NULL || strchr(name, '/') != NULL ||
        strchr(name, '\\') != NULL || !is_stored_file_name(name)) return false;
    if (!ensure_mutex()) return false;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    char full[96];
    bool ok = false;
    if (build_full_path(full, sizeof(full), name)) {
        /* Do not unlink the file currently being written. */
        if (pcap_file != NULL && strcmp(full, pcap_cur_path) == 0) {
            ESP_LOGW(TAG, "Refusing to delete the active capture %s", name);
        } else if (remove(full) == 0) {
            ok = true;
            ESP_LOGI(TAG, "Deleted %s", full);
        } else {
            ESP_LOGW(TAG, "Failed to delete %s", full);
        }
    }
    unlock_serializer();
    return ok;
}

bool pcap_serializer_delete_all(unsigned *removed)
{
    if (removed == NULL || !ensure_mutex()) return false;
    *removed = 0;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    bool ok = true;
    bool progress;
    do {
        progress = false;
        DIR *dir = opendir(PCAP_DIR_PATH);
        if (dir == NULL) {
            ok = false;
            break;
        }

        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (!is_stored_file_name(ent->d_name)) continue;

            char full[96];
            if (!build_full_path(full, sizeof(full), ent->d_name)) {
                ok = false;
                continue;
            }
            if (pcap_file != NULL && strcmp(full, pcap_cur_path) == 0) continue;
            if (remove(full) == 0) {
                (*removed)++;
                progress = true;
            } else if (errno != ENOENT) {
                ok = false;
            }
        }
        closedir(dir);
    } while (progress);
    unlock_serializer();
    return ok;
}

bool pcap_serializer_get_file_info(const char *name, pcap_file_info_t *out)
{
    if (name == NULL || out == NULL || !is_stored_file_name(name) ||
        strstr(name, "..") != NULL || strchr(name, '/') != NULL ||
        strchr(name, '\\') != NULL || !ensure_mutex()) return false;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    char full[96];
    struct stat st;
    bool ok = build_full_path(full, sizeof(full), name) && stat(full, &st) == 0 &&
              st.st_size >= 0;
    if (ok && pcap_file != NULL && strcmp(full, pcap_cur_path) == 0) {
        ok = flush_write_buf();
        if (ok) stat(full, &st);
    }
    if (ok) {
        strncpy(out->name, name, sizeof(out->name) - 1);
        out->name[sizeof(out->name) - 1] = '\0';
        out->size = (pcap_file != NULL && strcmp(full, pcap_cur_path) == 0)
                        ? pcap_size : (unsigned) st.st_size;
    }
    unlock_serializer();
    return ok;
}

bool pcap_serializer_write_text(const char *prefix, const uint8_t *ssid,
                                unsigned ssid_len, const char *text)
{
    if (prefix == NULL || text == NULL) return false;
    if (!ensure_mutex()) return false;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    build_ssid_tag(ssid, ssid_len);
    mkdir(PCAP_DIR_PATH, 0777);

    char path[96];
    pick_next_text_path(prefix, path, sizeof(path));

    char temp_path[96];
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int) sizeof(temp_path)) {
        storage_state = PCAP_STORAGE_IO_ERROR;
        unlock_serializer();
        return false;
    }

    FILE *file = fopen(temp_path, "w");
    if (file == NULL) {
        set_write_error();
        ESP_LOGE(TAG, "Failed to open %s", path);
        unlock_serializer();
        return false;
    }

    size_t len = strlen(text);
    bool ok = (fwrite(text, 1, len, file) == len);
    if (ok) ok = (fputc('\n', file) != EOF);
    if (fclose(file) != 0) {
        set_write_error();
        ok = false;
    }

    if (ok && rename(temp_path, path) != 0) {
        set_write_error();
        ok = false;
    }
    if (!ok) remove(temp_path);

    if (!ok) {
        ESP_LOGE(TAG, "Failed to write %s", path);
    } else {
        ESP_LOGI(TAG, "Saved result to %s", path);
    }
    unlock_serializer();
    return ok;
}

unsigned pcap_serializer_list_text(pcap_file_info_t *out, unsigned max)
{
    if (out == NULL || max == 0) return 0;
    if (!ensure_mutex()) return 0;

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return 0;
    }

    unsigned count = 0;
    DIR *dir = opendir(PCAP_DIR_PATH);
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && count < max) {
            /* Only generated PMKID result files belong in this list. */
            if (!is_result_name(ent->d_name)) continue;

            char full[96];
            if (!build_full_path(full, sizeof(full), ent->d_name)) continue;
            struct stat st;
            if (stat(full, &st) != 0) continue;

            strncpy(out[count].name, ent->d_name, sizeof(out[count].name) - 1);
            out[count].name[sizeof(out[count].name) - 1] = '\0';
            out[count].size = (unsigned)st.st_size;
            count++;
        }
        closedir(dir);
    }
    unlock_serializer();

    if (count > 1) qsort(out, count, sizeof(pcap_file_info_t), compare_file_info);
    return count;
}

#define PCAP_INSPECT_MAX_BYTES (256u * 1024u)

bool pcap_serializer_inspect(const char *name, pcap_inspect_t *out)
{
    if (name == NULL || out == NULL) return false;
    if (strstr(name, "..") != NULL || strchr(name, '/') != NULL ||
        strchr(name, '\\') != NULL || !is_stored_file_name(name)) return false;
    if (!ensure_mutex()) return false;

    memset(out, 0, sizeof(*out));

    lock_serializer();
    if (!mount_storage()) {
        unlock_serializer();
        return false;
    }

    char full[96];
    if (!build_full_path(full, sizeof(full), name)) {
        unlock_serializer();
        return false;
    }

    /* The file currently being written has buffered bytes that are not on flash
       yet; flush them so the browser sees what the capture actually holds. */
    if (pcap_file != NULL && strcmp(full, pcap_cur_path) == 0) {
        if (!flush_write_buf()) {
            unlock_serializer();
            return false;
        }
    }

    FILE *file = fopen(full, "rb");
    if (file == NULL) {
        unlock_serializer();
        return false;
    }

    uint8_t header[24];
    if (fread(header, 1, sizeof(header), file) != sizeof(header)) {
        fclose(file);
        unlock_serializer();
        return false;
    }

    unsigned scanned = (unsigned) sizeof(header);
    for (;;) {
        uint8_t rec[16];
        if (fread(rec, 1, sizeof(rec), file) != sizeof(rec)) break;

        unsigned incl = (unsigned) rec[8] | ((unsigned) rec[9] << 8) |
                        ((unsigned) rec[10] << 16) | ((unsigned) rec[11] << 24);
        if (incl == 0 || incl > 65535) break;
        scanned += (unsigned) sizeof(rec) + incl;
        if (scanned > PCAP_INSPECT_MAX_BYTES) {
            out->truncated = true;
            break;
        }

        uint8_t probe[64];
        unsigned want = incl < sizeof(probe) ? incl : (unsigned) sizeof(probe);
        if (fread(probe, 1, want, file) != want) break;
        if (fseek(file, (long) (incl - want), SEEK_CUR) != 0) break;

        out->frames++;

        if (want >= 24) {
            uint8_t fc0 = probe[0];
            uint8_t fc1 = probe[1];
            uint8_t ftype = (fc0 >> 2) & 0x03;
            uint8_t subtype = (fc0 >> 4) & 0x0F;

            if (ftype == 0 && subtype == 8 && !out->has_beacon) {
                unsigned pos = 36;   /* 24-byte header + 12-byte fixed part */
                while (pos + 2 <= want) {
                    uint8_t id = probe[pos];
                    uint8_t ie_len = probe[pos + 1];
                    if (pos + 2u + ie_len > want) break;
                    if (id == 0) {
                        unsigned n = ie_len < sizeof(out->ssid) - 1
                                         ? ie_len : sizeof(out->ssid) - 1;
                        memcpy(out->ssid, probe + pos + 2, n);
                        out->ssid[n] = '\0';
                        out->has_beacon = true;
                        break;
                    }
                    pos += 2u + ie_len;
                }
            } else if (ftype == 2) {
                unsigned off = 24;
                if ((fc1 & 0x03) == 3) off += 6;                 /* 4-address */
                if (subtype & 0x08) off += 2;                    /* QoS */
                if ((fc1 & 0x80) && (subtype & 0x08)) off += 4;  /* HT control */
                if (off + 8 <= want && probe[off] == 0xAA && probe[off + 1] == 0xAA &&
                    probe[off + 2] == 0x03 && probe[off + 6] == 0x88 &&
                    probe[off + 7] == 0x8E) {
                    out->eapol_frames++;
                }
            }
        }
    }

    out->bytes = scanned;
    fclose(file);
    unlock_serializer();
    return true;
}

pcap_storage_state_t pcap_serializer_get_state(void)
{
    if (!ensure_mutex()) return PCAP_STORAGE_IO_ERROR;
    lock_serializer();
    pcap_storage_state_t state = storage_state;
    unlock_serializer();
    return state;
}

bool pcap_serializer_get_storage_info(pcap_storage_info_t *info)
{
    if (info == NULL || !ensure_mutex()) return false;
    memset(info, 0, sizeof(*info));

    lock_serializer();
    if (!mount_storage()) {
        info->state = storage_state;
        unlock_serializer();
        return false;
    }

    size_t total = 0;
    size_t used = 0;
    esp_err_t ret = esp_littlefs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        /* Report the failure without touching storage_state: that flag gates the
           capture write path, so a read-only status query must never be able to
           abort a running capture. */
        info->state = PCAP_STORAGE_IO_ERROR;
        unlock_serializer();
        return false;
    }

    size_t pending = pcap_file != NULL ? write_buf_used : 0;
    size_t logical_used = used + pending;
    info->mounted = true;
    info->total_bytes = (unsigned) total;
    info->used_bytes = (unsigned) (logical_used > total ? total : logical_used);
    info->free_bytes = info->used_bytes < info->total_bytes
                       ? info->total_bytes - info->used_bytes : 0;
    info->state = storage_state;
    unlock_serializer();
    return true;
}
