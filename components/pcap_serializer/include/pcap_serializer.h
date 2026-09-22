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
bool pcap_serializer_init(void);

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
 * @brief Reads len bytes of the stored PCAP file starting at offset.
 * 
 * @param offset absolute offset into the stored file
 * @param buf destination buffer
 * @param len number of bytes to read
 * @return true on success
 */
bool pcap_serializer_read(unsigned offset, uint8_t *buf, unsigned len);

#endif /* PCAP_SERIALIZER_H */
