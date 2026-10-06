# AlphaPi ESP32 Wi-Fi 安全测试工具

这是面向 AlphaPi One S v1.7 开发板的 ESP32-S2R2 固件，用于经过授权的 Wi-Fi 安全测试、协议学习和抓包分析。项目保留了原始 ESP32 Wi-Fi Penetration Tool 的组件化结构，并加入了 AlphaPi 的屏幕、按键、中文网页界面和 Flash 文件管理功能。

> 只在你拥有或明确获准测试的网络上使用本项目。广播去认证、诱骗 AP 和拒绝服务功能可能会中断其他设备的网络连接，未经授权使用可能违法。

## 当前状态

- 目标芯片：ESP32-S2R2，单核 240 MHz，2 MB PSRAM。
- 目标 Flash：8 MB。
- 固件框架：PlatformIO + ESP-IDF 5.0.2。
- 本地屏幕：ST7789，160 x 128。
- 默认管理热点：SSID `ManagementAP`，密码 `mgmtadmin`。
- 顶层“被动”攻击入口仍未实现，网页中处于禁用状态；握手抓包中的“仅抓包”方法可以使用。
- GitHub Actions 会为 `main` 分支构建固件并上传构建产物。

## 功能

- 扫描附近接入点，显示网络名称、BSSID 和 RSSI 信号强度。
- 客户端探测，逐信道统计目标 AP 附近的客户端。
- WPA/WPA2 握手抓包和 HCCAPX 结果导出。
- PMKID 抓取和文本结果持久化。
- PCAP 文件写入 SPIFFS，并在网页中查看、下载和删除。
- 网页一次下载全部已保存文件，并显示存储总量、已用空间和剩余空间。
- 屏幕端提供设备信息、网络扫描、攻击配置和抓包文件管理。
- 设备日志可通过网页 `/logs` 接口读取。
- 存储分区挂载失败时不会自动格式化，避免历史抓包被清除；只有完全空白（全 `0xFF`）的分区会在首次使用时格式化。

## 攻击模式

| 类型 | 可选方式 | 当前说明 |
| --- | --- | --- |
| 被动 | 无 | 顶层入口保留但尚未实现 |
| 握手抓包 | 诱骗 AP、广播去认证、仅抓包 | 抓包成功率取决于目标 AP 和客户端行为 |
| PMKID | 自动连接尝试 | 不需要预先知道目标 Wi-Fi 密码 |
| 拒绝服务 | 诱骗 AP、广播去认证、全部组合 | 设备可能忽略广播去认证帧，效果不保证 |

握手 PCAP 会写入目标 AP 的第一帧 Beacon，以及分析器识别到的目标 EAPOL 数据帧。PCAP 中是否包含完整 ESSID 取决于目标 AP 是否公开广播 SSID；文件名中的标签不能替代抓包内的 ESSID。

## 硬件与 Flash 分区

| 分区 | 起始地址 | 大小 | 用途 |
| --- | ---: | ---: | --- |
| `nvs` | `0x9000` | 24 KB | ESP-IDF NVS |
| `phy_init` | `0xf000` | 4 KB | PHY 校准数据 |
| `factory` | `0x10000` | 3 MB | 应用固件 |
| `storage` | `0x310000` | 4 MB | SPIFFS 抓包和 PMKID 结果 |

抓包文件保存在 `storage` 分区。刷写启动器、分区表和应用时不需要擦除这个分区；不要执行整片 `erase-flash`，除非你已经备份了设备数据。

## 构建

### 本地构建

在本 README 所在目录执行：

```shell
pio run -e alphapi_esp32s2
```

本地上传可以使用：

```shell
pio run -e alphapi_esp32s2 -t upload
```

修改网页源文件后，需要重新生成嵌入式网页头文件：

```shell
python components/webserver/utils/gen_page_header.py components/webserver/utils/index.html components/webserver/pages/page_index.h page_index
```

### GitHub Actions

工作流位于 [`build.yml`](.github/workflows/build.yml)。在 GitHub 的 Actions 页面手动运行，或向 `main` 分支推送提交后，下载对应运行记录中的 `alphapi_esp32s2-firmware` 工件。工件包含：

- `bootloader.bin`
- `partitions.bin`
- `firmware.bin`

工作流地址：<https://github.com/swtmaxx/alphapi-wifi-penetration-tool/actions/workflows/build.yml>

### GitHub Releases

发布版本时创建并推送语义化版本标签，例如：

```shell
git tag -a v1.0.0 -m "AlphaPi v1.0.0"
git push origin v1.0.0
```

[`release.yml`](.github/workflows/release.yml) 会在标签推送后自动执行构建并创建 GitHub Release。Release 包含：

- `AlphaPi-vX.Y.Z.zip` 和 `AlphaPi-vX.Y.Z.tar.gz`；
- 三段固件和从 `0x0` 写入的合并固件；
- 中文刷写说明、网页刷写器、启动脚本和 SHA-256 校验文件；
- `BUILD-INFO.txt`、`IMAGE-INFO.txt` 和源码提交信息。

也可以在 Actions 页面手动运行 `Release AlphaPi Firmware`，输入一个已经存在的 `vX.Y.Z` 标签。带有 `-rc`、`-beta` 等后缀的标签会自动标记为预发布版本。

## 刷写

确认设备串口后，把下面的 `COM5` 替换为实际端口。命令使用 esptool v5 的 `write-flash` 语法：

```shell
python -m esptool --chip esp32s2 --port COM5 --baud 460800 write-flash --flash-mode dio --flash-freq 40m --flash-size 8MB 0x1000 bootloader.bin 0x8000 partitions.bin 0x10000 firmware.bin
```

这条命令只更新启动器、分区表和应用区，不写入 `0x310000` 起的 `storage` 分区。刷写前仍建议保留完整 Flash 备份。

## 第一次使用

1. 给 AlphaPi 上电，等待设备启动管理热点。
2. 手机或电脑连接 `ManagementAP`，默认密码为 `mgmtadmin`。
3. 打开 <http://192.168.4.1/>。
4. 进入网络扫描，选择目标 AP 后配置攻击类型和超时时间。
5. 抓包结束后，在“抓包文件”区域下载对应的 PCAP 或 PMKID 结果。

管理热点密码可以在 ESP-IDF 的 `Wi-Fi Controller -> Management AP` 配置中修改。公开发布或长期使用时，不要继续使用默认密码。

## 屏幕菜单

屏幕主菜单包含三个页面：

- **设备信息**：管理热点名称、密码、地址、抓包数量、存储剩余空间和管理信道。
- **网络扫描**：扫描附近 AP，选择目标并进入攻击配置。
- **抓包文件**：浏览、删除单个文件或删除全部历史结果。

攻击过程中，状态页会显示当前类型、PCAP 帧数、文件大小、自动停止诊断信息和存储错误。

## 抓包文件

新抓包文件使用递增编号和可选 SSID 标签命名，例如：

```text
capture_001_HomeWiFi.pcap
capture_002.pcap
pmkid_001_HomeWiFi.txt
```

文件名标签只保留 ASCII 字母、数字、连字符和下划线；中文或其他字符会被替换为下划线。隐藏 SSID 可能生成没有标签的文件名，但不会因此自动获得真实 ESSID。

设备使用 4 MB SPIFFS 保存这些文件，不自动分卷，也不自动删除旧文件。空间不足或写入失败时，攻击会停止并在网页和屏幕上报告存储错误。

挂载失败时不会自动格式化分区：已经写入过数据的分区即使挂载失败也会原样保留，网页和屏幕会报告 `mount_error`，请先自行备份。唯一的例外是全新刷写后仍然完全空白（全 `0xFF`）的分区，它会在首次使用时自动格式化，否则设备无法保存任何抓包。

## 网页接口

网页使用管理热点提供以下操作：

- `/`：中文控制界面。
- `/ap-list`：扫描 AP 列表。
- `/count-clients`：开始客户端探测。
- `/count-clients/status`：读取客户端探测进度和结果。
- `/run-attack`：提交攻击配置。
- `/status`：读取当前攻击状态和结果。
- `/capture.pcap`：下载当前 PCAP。
- `/capture.hccapx`：下载当前 HCCAPX 结果。
- `/pcap-list`：列出所有已保存的 PCAP 和 PMKID 文件。
- `/capture-file?name=...`：下载指定文件。
- `/pcap-delete`、`/pcap-delete-all`：删除文件。
- `/storage-status`：读取 SPIFFS 空间和错误状态。
- `/logs`：读取最近的设备日志。

客户端探测和攻击会占用 ESP32 的无线电信道，过程中管理热点可能暂时无法访问；完成后的信道恢复行为取决于具体攻击方式，若网页未恢复，请等待设备结束任务后重新连接管理热点。

## 已知限制

- 顶层被动攻击模式尚未实现。
- 广播去认证是否让客户端掉线取决于客户端实现、AP 配置和信号环境。
- 隐藏 SSID 的 Beacon 不包含网络名称，抓包文件名中的标签不能替代协议中的 ESSID。
- ESP32 负责抓包和结果导出，不负责离线密码破解；后续分析需要在授权环境中使用其他工具。
- 本项目没有自动分卷和自动清理策略，长期抓包前请查看剩余空间。

## 目录结构

```text
main/                         攻击流程、屏幕 UI 和应用入口
components/wifi_controller/   AP、STA、扫描、嗅探和客户端探测
components/frame_analyzer/    EAPOL/PMKID 帧分析
components/pcap_serializer/   PCAP 和 SPIFFS 文件管理
components/hccapx_serializer/ HCCAPX 结果序列化
components/webserver/         HTTP API 和中文网页
components/display/            AlphaPi ST7789 显示驱动和字库
components/wsl_bypasser/       原始 802.11 帧发送支持
doc/                           理论说明、图示和图片
release/                       网页刷写器、发布说明和第三方许可
firmware/、backups/            工作区本地恢复资料，不属于本公开仓库
```

开发时不要提交抓包文件、完整 Flash 备份、私有固件、设备凭据或访问令牌。安全问题和日志提交规则见 [`SECURITY.md`](SECURITY.md)。本仓库不提交任何编译产物（`build/` 已被忽略），固件请从 GitHub Actions 工件或 Release 页面获取。

## 贡献

欢迎提交问题和 Pull Request。新增 C/C++ 接口请使用 Doxygen 注释，网页修改后同时提交生成的 `components/webserver/pages/page_index.h`。提交中请说明目标芯片、Flash 容量、构建环境和硬件验证结果。

## 许可证与来源

本项目使用 MIT License，详见 [`LICENSE`](LICENSE)。其中部分组件和设计来自原始 ESP32 Wi-Fi Penetration Tool 及 ESP32-Deauther 相关项目，具体说明见各组件 README 和源文件注释。请保留原作者的版权和许可证声明。

### 原始仓库与原始 README

本仓库是面向 AlphaPi One S v1.7、ESP32-S2R2 的独立适配版，不是原始项目的官方仓库。

- 原始仓库：[`risinek/esp32-wifi-penetration-tool`](https://github.com/risinek/esp32-wifi-penetration-tool)
- 原始 README：[`README.md`](https://github.com/risinek/esp32-wifi-penetration-tool/blob/master/README.md)
- ESP32-S2 参考分支：[`ZhengLinLei/esp32-wifi-penetration-tool/tree/esp32s2`](https://github.com/ZhengLinLei/esp32-wifi-penetration-tool/tree/esp32s2)
- 当前 AlphaPi 仓库：[`swtmaxx/alphapi-wifi-penetration-tool`](https://github.com/swtmaxx/alphapi-wifi-penetration-tool)
