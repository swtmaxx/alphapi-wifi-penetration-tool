# ESP32 Wi-Fi Penetration Tool
## PCAP Serializer component

This component writes captured 802.11 frames to a PCAP file on the `storage`
SPIFFS partition and manages the files that live there.

It is based on the [Wireshark LibPCAP file format reference](https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat).
Frames are accumulated in a small RAM buffer and flushed to Flash when it fills,
so the Wi-Fi callback never blocks on a Flash write per frame.

Files are named `capture_<index>[_<ssid tag>].pcap`; PMKID results are written as
`pmkid_<index>[_<ssid tag>].txt`. The SSID tag keeps only ASCII letters, digits,
`-` and `_`, so a captured name can never break out of the capture directory.

### Mount behaviour

The partition is mounted on first use. It is **not** formatted when mounting
fails, because a partition that still holds bytes may contain captures the user
has not downloaded yet. The only exception is a completely blank (all `0xFF`)
partition, which is formatted so a freshly flashed device can capture without
extra steps. Mount failures are reported through `pcap_serializer_get_state()`
as `PCAP_STORAGE_MOUNT_ERROR`.

## Usage
1. Initialise a new capture with `pcap_serializer_init(ssid, ssid_len)`; this
   mounts the partition, picks the next free index and writes the PCAP header.
1. Append frames with `pcap_serializer_append_frame(buffer, size, ts_usec)`.
   The function returns `false` once storage failed; the caller should then stop
   the capture and report `pcap_serializer_get_state()`.
1. Flush and close with `pcap_serializer_deinit()`.

### Reading back
- `pcap_serializer_get_size()` / `pcap_serializer_get_frame_count()` report
  progress for the current capture.
- `pcap_serializer_read()` streams the current capture, `pcap_serializer_read_file()`
  streams any stored file by name.
- `pcap_serializer_list_page()` enumerates captures and PMKID results,
  `pcap_serializer_get_file_info()` looks one file up,
  `pcap_serializer_delete()` / `pcap_serializer_delete_all()` remove them
  (the file currently being written is never deleted).
- `pcap_serializer_write_text()` stores a small text result (used for the
  hashcat-ready PMKID line) next to the captures.
- `pcap_serializer_get_storage_info()` reports total/used/free bytes.

All entry points are internally locked, so they may be called from the HTTP
server task while a capture is running.

## Reference
Doxygen API reference available
