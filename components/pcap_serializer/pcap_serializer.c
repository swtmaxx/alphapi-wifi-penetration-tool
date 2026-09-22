/**
 * @file pcap_serializer.c
 * @brief PCAP serializer that streams captured frames to SPIFFS on Flash.
 *
 * Frames are accumulated in a small RAM write buffer and flushed to the
 * capture file whenever it fills, so the WiFi callback never blocks on a
 * Flash write for every single frame.
 */
#include "pcap_serializer.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_spiffs.h"
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
/* Indexed name with an SSID tag, e.g. capture_007_MyWiFi.pcap */
#define PCAP_FILE_PATH_SSID_FMT PCAP_BASE_PATH "/capture_%03u%s.pcap"
#define PCAP_SSID_TAG_MAX 24
#define PCAP_DIR_PATH    PCAP_BASE_PATH
#define PCAP_FILE_MASK   8
#define WRITE_BUF_SIZE   4096

static unsigned pcap_size = 0;
static FILE *pcap_file = NULL;
static char pcap_cur_path[64] = PCAP_FILE_PATH;
static unsigned pcap_file_index = 1;
static char pcap_ssid_tag[PCAP_SSID_TAG_MAX + 1] = "";
static uint8_t write_buf[WRITE_BUF_SIZE];
static unsigned write_buf_used = 0;
static bool spiffs_mounted = false;
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

static bool mount_spiffs(void)
{
    if (spiffs_mounted) return true;

    esp_vfs_spiffs_conf_t conf = {
        .base_path = PCAP_BASE_PATH,
        .partition_label = NULL,
        .max_files = 2,
        .format_if_mount_failed = true,
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SPIFFS (%s)", esp_err_to_name(ret));
        return false;
    }
    spiffs_mounted = true;
    return true;
}

static bool flush_write_buf(void)
{
    if (pcap_file == NULL || write_buf_used == 0) return true;
    size_t written = fwrite(write_buf, 1, write_buf_used, pcap_file);
    if (written != write_buf_used) {
        ESP_LOGE(TAG, "Failed to write PCAP buffer (%u/%u bytes)",
                 (unsigned) written, write_buf_used);
        return false;
    }
    write_buf_used = 0;
    if (fflush(pcap_file) != 0) {
        ESP_LOGE(TAG, "Failed to flush PCAP file");
        return false;
    }
    return true;
}

static void append_bytes(const uint8_t *data, unsigned size)
{
    while (size > 0) {
        unsigned space = WRITE_BUF_SIZE - write_buf_used;
        unsigned copy = size > space ? space : size;
        memcpy(&write_buf[write_buf_used], data, copy);
        write_buf_used += copy;
        data += copy;
        size -= copy;
        if (write_buf_used == WRITE_BUF_SIZE) flush_write_buf();
    }
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

static void pick_next_capture_path(void)
{
    DIR *dir = opendir(PCAP_DIR_PATH);
    unsigned max_index = 0;
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            unsigned idx = 0;
            /* Accept both capture_NNN.pcap and capture_NNN_tag.pcap. */
            if (sscanf(ent->d_name, "capture_%u", &idx) == 1 ||
                sscanf(ent->d_name, "capture_%u_", &idx) == 1) {
                if (idx > max_index) max_index = idx;
            }
        }
        closedir(dir);
    }
    pcap_file_index = max_index + 1;

    if (pcap_ssid_tag[0] != '\0') {
        snprintf(pcap_cur_path, sizeof(pcap_cur_path),
                 PCAP_FILE_PATH_SSID_FMT, pcap_file_index, pcap_ssid_tag);
    } else {
        snprintf(pcap_cur_path, sizeof(pcap_cur_path),
                 PCAP_FILE_PATH_FMT, pcap_file_index);
    }
}

bool pcap_serializer_init(const uint8_t *ssid, unsigned ssid_len)
{
    build_ssid_tag(ssid, ssid_len);

    if (!ensure_mutex()) return false;
    lock_serializer();

    if (!mount_spiffs()) {
        unlock_serializer();
        return false;
    }

    if (pcap_file != NULL) {
        flush_write_buf();
        fclose(pcap_file);
        pcap_file = NULL;
    }

    mkdir(PCAP_DIR_PATH, 0777);
    pick_next_capture_path();

    pcap_file = fopen(pcap_cur_path, "w+b");
    if (pcap_file == NULL) {
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
    append_bytes((uint8_t *)&pcap_global_header, sizeof(pcap_global_header_t));
    pcap_size = sizeof(pcap_global_header_t);
    unlock_serializer();
    return true;
}

void pcap_serializer_append_frame(const uint8_t *buffer, unsigned size, unsigned ts_usec)
{
    if (size == 0) return;
    if (buffer == NULL || !ensure_mutex()) return;

    lock_serializer();
    if (pcap_file == NULL) {
        unlock_serializer();
        return;
    }

    if (size > SNAPLEN) size = SNAPLEN;

    pcap_record_header_t pcap_record_header = {
        .ts_sec = ts_usec / 1000000,
        .ts_usec = ts_usec % 1000000,
        .incl_len = size,
        .orig_len = size,
    };

    append_bytes((uint8_t *)&pcap_record_header, sizeof(pcap_record_header_t));
    append_bytes(buffer, size);
    pcap_size += sizeof(pcap_record_header_t) + size;
    unlock_serializer();
}

void pcap_serializer_deinit(void)
{
    if (!ensure_mutex()) return;
    lock_serializer();
    flush_write_buf();
    if (pcap_file != NULL) {
        fclose(pcap_file);
        pcap_file = NULL;
    }
    write_buf_used = 0;
    /* Keep the mounted partition and size available for a later download. */
    unlock_serializer();
}

unsigned pcap_serializer_get_size(void)
{
    if (!ensure_mutex()) return 0;
    lock_serializer();
    unsigned size = pcap_size;
    unlock_serializer();
    return size;
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
    if (!mount_spiffs()) {
        unlock_serializer();
        return 0;
    }

    unsigned count = 0;
    DIR *dir = opendir(PCAP_DIR_PATH);
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && count < max) {
            unsigned idx = 0;
            /* Accept capture_NNN.pcap and capture_NNN_tag.pcap. */
            if (sscanf(ent->d_name, "capture_%u", &idx) != 1) continue;

            char full[96];
            snprintf(full, sizeof(full), PCAP_BASE_PATH "/%s", ent->d_name);
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
    qsort(out, count, sizeof(pcap_file_info_t), compare_file_info);
    return count;
}

bool pcap_serializer_read_file(const char *name, unsigned offset, uint8_t *buf, unsigned len)
{
    if (name == NULL || (buf == NULL && len != 0)) return false;
    if (strstr(name, "..") != NULL || strchr(name, '/') != NULL) return false;
    if (!ensure_mutex()) return false;

    lock_serializer();
    if (!mount_spiffs()) {
        unlock_serializer();
        return false;
    }

    char full[80];
    snprintf(full, sizeof(full), PCAP_BASE_PATH "/%s", name);

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