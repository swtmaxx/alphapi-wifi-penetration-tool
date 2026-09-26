# AlphaPi Wi-Fi 安全测试固件 Release 包

本目录由 GitHub Actions 自动打包，适用于 AlphaPi ESP32-S2R2 开发板。Release 页面会同时提供三段固件、合并固件、网页刷写器和校验文件。

> 只在你拥有或明确获准测试的网络上使用 Wi-Fi 扫描、抓包和安全测试功能。

## 来源

本固件是 AlphaPi 的适配版，不是原始项目的官方发行包。

- 原始仓库：<https://github.com/risinek/esp32-wifi-penetration-tool>
- 原始 README：<https://github.com/risinek/esp32-wifi-penetration-tool/blob/master/README.md>
- ESP32-S2 参考分支：<https://github.com/ZhengLinLei/esp32-wifi-penetration-tool/tree/esp32s2>
- 当前 AlphaPi 仓库：<https://github.com/swtmaxx/alphapi-wifi-penetration-tool>

## 适用设备

- 芯片：ESP32-S2 / ESP32-S2R2
- Flash：8 MB
- USB VID:PID：`2F4E:0104`

网页刷写器会检查设备型号、芯片和 Flash 容量。不要将本包用于其他 ESP32 板卡。

## 推荐：三段刷写

三段方式只更新启动器、分区表和应用区，保留 `0x310000` 起的 `storage` SPIFFS 分区，因此已有抓包文件和 PMKID 结果会保留。

1. 双击 `start-flasher.cmd`，或在本目录运行 `python -m http.server 8000 --bind 127.0.0.1`。
2. 使用桌面版 Chrome 或 Edge 打开 `http://localhost:8000/alphapi-one-s-web-flasher.html`。
3. 让设备进入 ESP32-S2 ROM 下载模式，选择 VID:PID 为 `2F4E:0104` 的串口。
4. 点击“三段固件布局”，再点击“批量导入”，选择 `firmware` 文件夹中的三个 BIN 文件。
5. 确认地址如下：

   ```text
   0x001000  bootloader.bin
   0x008000  partitions.bin
   0x010000  firmware.bin
   ```

6. 点击“开始烧录”，完成后按实体 Reset 键或重新上电。

网页默认使用 DIO、40 MHz、8 MB Flash，并且不会执行整片擦除。

## 合并固件

Release 根目录中的 `AlphaPi-<版本标签>.bin` 是从 `0x0` 写入的合并镜像。

- 会覆盖 `0x9000` 的 NVS 和 `0xf000` 的 PHY 数据，原有管理热点配置会丢失。
- 不会写入 `0x310000` 起的 `storage` 分区，抓包文件仍然保留。
- 刷写后需要重新连接管理热点并重新配置网络。

命令行示例：

```powershell
python -m esptool --chip esp32s2 --port COM5 --baud 460800 `
  write-flash --flash-mode dio --flash-freq 40m --flash-size 8MB `
  0x000000 AlphaPi-<版本标签>.bin
```

## 命令行三段刷写

```powershell
python -m esptool --chip esp32s2 --port COM5 --baud 460800 `
  write-flash --flash-mode dio --flash-freq 40m --flash-size 8MB `
  0x001000 firmware/bootloader.bin `
  0x008000 firmware/partitions.bin `
  0x010000 firmware/firmware.bin
```

刷写前请确认串口号，并保留完整 Flash 备份。不要执行 `erase-flash`，除非你已经确认不需要设备中的抓包文件。

## 分区与文件

| 分区 | 起始地址 | 大小 | 用途 |
| --- | ---: | ---: | --- |
| `nvs` | `0x009000` | 24 KB | ESP-IDF NVS |
| `phy_init` | `0x00f000` | 4 KB | Wi-Fi PHY 校准 |
| `factory` | `0x010000` | 3 MB | 应用固件 |
| `storage` | `0x310000` | 4 MB | PCAP、HCCAPX 和 PMKID 文件 |

Release 包中的 `BUILD-INFO.txt` 记录源码提交和 Actions 运行编号，`IMAGE-INFO.txt` 记录 ESP32-S2 镜像校验结果，`SHA256SUMS.txt` 校验所有发布文件。

网页刷写器内嵌的第三方库许可见 `LICENSE.esptool-js`（Apache-2.0）和 `LICENSE.pako`（MIT）。

## 限制

- 网页刷写器不能替代 GPIO0/EN 硬件控制；设备需要先进入 ROM 下载模式。
- USB 串口在复位时可能短暂重新枚举，写入完成后手动 Reset 即可。
- 发布包不包含抓包文件、完整 Flash 备份、设备凭据或私有密钥。
