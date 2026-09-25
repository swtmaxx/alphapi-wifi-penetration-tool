# ESP32 Wi-Fi Penetration Tool
## PCAP Serializer component

This component streams frames into persistent PCAP files in the SPIFFS
`storage` partition. PMKID Hashcat lines are stored as text files beside them.

It's based on [Wiresharks LibPCAP file format referenc](https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat).
Capture files use an increasing index and optional SSID tag. Existing files
are not rotated or automatically removed. When storage is full or a write
fails, the serializer reports failure; it never formats the partition or
deletes older files automatically.

## Usage
1. Call `pcap_serializer_init()` to create a new capture file.
2. Append frames with `pcap_serializer_append_frame()` and check its return value.
3. Call `pcap_serializer_deinit()` to flush and close the file; check its return value.
4. Enumerate files with `pcap_serializer_list_page()` and delete only on an explicit user request.

## Reference
Doxygen API reference available
