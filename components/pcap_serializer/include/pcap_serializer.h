/**
 * @file pcap_serializer.h
 * @brief PCAP serializer that streams captured frames to SPIFFS on Flash.
 */
#ifndef PCAP_SERIALIZER_H
#define PCAP_SERIALIZER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief PCAP global header
 * 
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
typedef struct {
            uint32_t magic_number;   /* magic number */
            uint16_t version_major;  /* major version number */
            uint16_t version_minor;  /* minor version number */
            int32_t  thiszone;       /* GMT to local correction */
            uint32_t sigfigs;        /* accuracy of timestamps */
            uint32_t snaplen;        /* max length of captured packets, in octets */
            uint32_t network;        /* data link type */
} pcap_global_header_t;

/**
 * @brief PCAP record header
 * 
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
typedef struct {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcap_record_header_t;

/**
 * @brief Mounts SPIFFS, opens the capture file and writes the PCAP global header.
 *
 * Has always to be called before pcap_serializer_append_frame().
 * @return true if the capture file is ready for appending.
 */
/**
 * @param ssid SSID of the target AP, used as an optional file-name tag so the
 *             capture can be identified later. May be NULL.
 * @param ssid_len number of valid bytes in ssid
 */
bool pcap_serializer_init(const uint8_t *ssid, unsigned ssid_len);

/**
 * @brief Appends a frame. Data is buffered in RAM and flushed to Flash when full.
 * 
 * @param buffer frame buffer that should be appended to PCAP
 * @param size size of frame buffer
 * @param ts_usec timestamp of captured frame in microseconds
 */
void pcap_serializer_append_frame(const uint8_t *buffer, unsigned size, unsigned ts_usec);

/**
 * @brief Flushes remaining bytes and closes the capture file.
 * 
 */
void pcap_serializer_deinit(void);

/**
 * @brief Total size of the stored PCAP file in bytes.
 * 
 * @return unsigned
 */
unsigned pcap_serializer_get_size(void);

/**
 * @brief Number of frames appended to the current capture.
 *
 * Unlike the attack status byte count this reflects what actually reached the
 * PCAP serializer, so it is the honest progress indicator during a capture.
 */
unsigned pcap_serializer_get_frame_count(void);

/**
 * @brief Reads len bytes of the stored PCAP file starting at offset.
 * 
 * @param offset absolute offset into the stored file
 * @param buf destination buffer
 * @param len number of bytes to read
 * @return true on success
 */
bool pcap_serializer_read(unsigned offset, uint8_t *buf, unsigned len);

/** Maximum number of capture files returned by pcap_serializer_list(). */
#define PCAP_LIST_MAX 32

/**
 * @brief Information about one stored capture file.
 */
typedef struct {
    char name[32];      /**< file name inside the capture directory, e.g. capture_001.pcap */
    unsigned size;      /**< file size in bytes */
} pcap_file_info_t;

/**
 * @brief Enumerate stored capture files, newest index last.
 *
 * @param out caller-owned array
 * @param max capacity of out
 * @return number of files written to out
 */
unsigned pcap_serializer_list(pcap_file_info_t *out, unsigned max);

/**
 * @brief Reads bytes from a specific stored capture file.
 *
 * @param name file name as returned by pcap_serializer_list()
 * @param offset absolute offset into that file
 * @param buf destination buffer
 * @param len number of bytes to read
 * @return true on success
 */
bool pcap_serializer_read_file(const char *name, unsigned offset, uint8_t *buf, unsigned len);

/**
 * @brief Delete one stored file from the capture directory.
 *
 * @param name file name as returned by pcap_serializer_list()
 * @return true when the file is gone afterwards
 */
bool pcap_serializer_delete(const char *name);

/**
 * @brief Write a small text result next to the captures.
 *
 * Used for PMKID output, which is a single hashcat-ready line rather than a
 * frame stream, so it needs no PCAP container.
 *
 * @param prefix file-name prefix, e.g. "pmkid"
 * @param ssid   target SSID, used as an optional name tag (may be NULL)
 * @param ssid_len number of valid bytes in ssid
 * @param text   NUL-terminated content to store
 * @return true on success
 */
bool pcap_serializer_write_text(const char *prefix, const uint8_t *ssid,
                                unsigned ssid_len, const char *text);

/**
 * @brief List stored text result files (same directory as captures).
 *
 * @param out caller-owned array
 * @param max capacity of out
 * @return number of files written
 */
unsigned pcap_serializer_list_text(pcap_file_info_t *out, unsigned max);

#endif /* PCAP_SERIALIZER_H */
