<!-- 项目logo -->
<p align="center">
  <img src="https://raw.githubusercontent.com/sinspired/subs-check/main/doc/logo/logo.png" alt="Project Logo" width="200"/>
</p>

<h2 align="center">Subs-Check</h1>

<p align="center" color="#6a737d">
High-performance proxy subscription checker.
</p>

[![Release](https://img.shields.io/github/v/release/sinspired/subs-check?logo=github)](https://github.com/sinspired/subs-check/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/sinspired/subs-check?logo=docker)](https://hub.docker.com/r/sinspired/subs-check)
[![GHCR](https://img.shields.io/badge/ghcr.io-available-blue?logo=github)](https://ghcr.io/sinspired/subs-check)
[![GitHub Release](https://img.shields.io/github/v/release/sinspired/SubsCheck-Win-GUI?display_name=release&style=social&logo=github&label=WindowsGUI界面)](https://github.com/sinspired/SubsCheck-Win-GUI/releases/latest)

# 🚀 subs-check 性能版

[ **测活、测速、媒体解锁** ] 检测工具，支持自动无缝版本更新；支持100-1000高并发低占用运行，检测结果更准确。全新设计，适配PC和手机设备的现代 WebUI 配置管理界面，自动生成 `mihomo` 和 `singbox` 订阅，支持一键复制分享。

## ✨ 新增

- ⚡ [**自适应流水线高并发模式**](#1-测活-测速-媒体检测分阶段流水线自适应高并发)  
- 🏷️ [**增强位置标签**](#2-增强位置标签)  
- 🧠 [**优化内存**](#3-优化内存)  
- 🔀 [**智能节点乱序**](#4-智能节点乱序减少节点被测速-测死-的概率)  
- 📂 [**历次检测可用节点保存与加载**](#5-保存并加载-历次-检测可用节点)  
- 🌐 [**自动检测代理**](#-优化系统代理和github代理设置可选)
- 💻 支持 **Windows / Linux / macOS 多平台部署**，Windows 可搭配 [GUI程序](https://github.com/sinspired/SubsCheck-Win-GUI) 使用
---
### 🔄 版本特性

- 💡 自 **v1.9.0** 起：支持 [自动检查更新，无缝升级新版本](#6-自动检查更新无缝升级新版本)。  
- 📱 自 **v1.9.3** 起：全新设计的 [WebUI管理界面](#-重新设计的-webui管理界面)，优化小屏设备访问体验。  
- 📦 自 **v1.9.7** 起：支持 [自动生成开箱即用的singbox配置](#新增分享菜单项自动生成singbox订阅支持一键分享)（兼容 iOS 设备），支持在 WebUI 一键复制订阅。  
- ⚙️ 自 **v1.9.9** 起：升级配置编辑器，支持根据 `config.yaml` 自动补全。

---
🐳 教程：[Docker 部署](#-docker-运行)  

📘 教程：[随时随地管理 subs-check 检测与订阅](#️-cloudflare-tunnel隧道映射外网访问)  

> ⚠️ 注意事项
>
> 功能更新频繁，请务必查看最新的 [配置文件示例](https://github.com/sinspired/subs-check/blob/main/config/config.example.yaml) 以获取最新功能支持。  

## ✨ 特性

- **📦 自动检查更新，无缝升级新版本**
- **📈 自适应高并发模式**
- **🎫 增强位置标签显示**
- **🚦 检测系统代理、GitHub代理可用性，并自动设置**
- **🔗 订阅合并**
- **🔍 节点可用性检测**
- **🗑️ 节点去重**
- **⏱️ 节点测速**
- **🎬 流媒体平台解锁检测**
- **✏️ 节点重命名**
- **🔄 任意格式订阅转换**
- **🔔 支持100+通知渠道**
- **🌐 内置 Sub-Store**
- **🖥️ WEB 控制面板**
- **⏰ 支持 Crontab 表达式**
- **🖥️ 多平台支持**

## 📸 预览

![preview](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/preview.png)  
![result](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/results.png)

### ✨ 重新设计的 WebUI管理界面

![login](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/login.png)
![WebUI](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/WebUI.png)

### ⚡新增分享菜单项，自动生成singbox订阅，支持一键分享

|                                  |                                        |                                        |
| -------------------------------- | -------------------------------------- | -------------------------------------- |
|![sub-store](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/sub-store.png) | ![shareMenu](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/share-menu.png)  |  ![singbox](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/sing-box.png)  |

|                                  |                                        |
| -------------------------------- | -------------------------------------- |
| ![tgram](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/tgram.png) | ![dingtalk](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/images/dingtalk.png) |

## **✨ 新增功能和性能优化**

### 1. 测活-测速-媒体检测，分阶段流水线，自适应高并发

通过将测活阶段并发数提升`100-1000`（*主要受限于设备 CPU 和路由器芯片性能，几乎不占用带宽*），同时将测速阶段并发数保持在较低水平（如 `8-32`，以减轻带宽竞争）。大幅提高性能，数倍缩短整体检测时间，并使测速结果更准确！

```yaml
# 新增设置项:
alive-concurrent: 200  # 测活并发数
speed-concurrent: 32   # 测速并发数
media-concurrent: 100  # 流媒体检测并发数
```

### 2. 增强位置标签

> 示例：🇺🇸US¹-SG⁰_3|2.5MB/s|6%|GPT⁺|TK-US|YT-US|NF|D+|X

- BadCFNode(无法访问CF网站的节点)：`HK⁻¹`
- CFNodeWithSameCountry(实际位置与cdn位置一致)：`HK¹⁺`
- CFNodeWithDifferentCountry(实际位置与cdn位置不一致)：`HK¹-US⁰`
- NodeWithoutCF(未使用CF加速的节点)：`HK²`
  
前两位字母是实际浏览网站识别的位置，`-US⁰` 为使用CF CDN服务的网站识别的位置，比如GPT， X等

```yaml
# 新增设置项:
drop-bad-cf-nodes: false  # 是否丢弃低质量的CF节点
enhanced-tag: false       # 是否开启 增强位置标签
maxmind-db-path: ""       # 指定位置数据库
```

### 3. 优化内存

`检测期下降18%，检测结束下降49%`，对内存敏感可以使用 `i386` 版本，对内存不敏感可以使用 `x64` 版本，性能略有提升，cpu占用更低。

- 去重后，释放原数据
- 结束检测，手动释放节点缓存
- 每个检测任务结束，结束空闲tcp连接占用
- pre-release 使用绿茶垃圾回收(测试中)

```powershell
# 内存监控数据:
[19:13:30] Start: PID=9040 mem=667.80 MB
[19:26:38] BigChange(>=20%) reached in 13m8.0320213s, mem=102.71 MB
[19:44:37] Down 1 step(s) of 10MB, mem=98.72 MB
[20:37:40] Down 1 step(s) of 10MB, mem=83.64 MB
[20:42:41] Down 3 step(s) of 10MB, mem=59.54 MB
```

### 4. 智能节点乱序，减少节点被测速 “测死” 的概率

```yaml
# 新增配置项:
# 相似度阈值(Threshold)大致对应网段
# 1.00 /32（完全相同 IP）
# 0.75 /24（前三段相同）
# 0.50 /16（前两段相同）
# 0.25 /8（第一段相同）
# 以下设置仅能 [减少] 节点被测速测死的概率, 无法避免被 "反代机房" 中断节点
threshold:  0.75
```

### 5. 保存并加载 `历次` 检测可用节点

可有效缓解网络环境恶劣导致的问题

```powershell
# 保存并加载 "上次检测成功的节点" 和 "历次检测成功的节点"
# keep-success-proxies: true
2025-09-25 15:52:25 INF 已获取节点数量: 15872
2025-09-25 15:52:25 INF 去重后节点数量: 11788
2025-09-25 15:52:25 INF 已加载上次检测可用节点，数量: 110
2025-09-25 15:52:25 INF 已加载历次检测可用节点，数量: 536
2025-09-25 15:52:25 INF 节点乱序, 相同 CIDR/24 范围 IP 的最小间距: 785
2025-09-25 15:52:25 INF 开始检测节点
2025-09-25 15:52:25 INF 当前参数 enable-speedtest=true media-check=true drop-bad-cf-nodes=false auto-concurrent=true concurrent=100 :alive=515 :speed=28 :media=138 timeout=5000 min-speed=512 download-timeout=10 download-mb=20
进度: [===========================================> ] 95.7% (11280/11788) 可用: 133
```

### 6. 自动检查更新，无缝升级新版本

- 软件启动时更新：重启后打开新窗口
- 定时更新任务：静默重启，如需关闭任务，直接关闭终端控制台即发送关闭信号

```yaml
# 是否开启新版本更新
# 支持启动时检查更新及定时更新任务,无缝升级新版本
# 支持apprise API通知渠道
# true: 自动更新; false: 不更新
update: false
# 启动时检查更新版本
update-on-startup: true
# 定时检查更新
# "0 0,9,21 * * *" 默认每天0点,9点,21点检查更新
cron-chek-update: "0 0,9,21 * * *"
# 使用预发布版本
prerelease: false
```

## ⚙️ Cloudflare Tunnel（隧道映射）外网访问

> WebUI 经过全新设计，添加了 **logo 图标** 等资源，因此需要比原版额外增加一个 **static 资源路径**。

---

### 🚀 简易操作步骤

1. 🔑 登录 **Cloudflare (CF)**，左侧菜单栏点击 **`Zero Trust`**  
2. 🌐 在新页面，左侧菜单栏点击 **`网络` → `Tunnels` → `创建隧道` → `选择 Cloudflared`**  
3. 🛠️ 按提示操作：  
   - `为隧道命名`  
   - `安装并运行连接器`  
   - `路由隧道`  
4. ✅ 创建完成后，在 **`Tunnels`** 页面会出现你创建的隧道  
   - 点击 **隧道名称** → **编辑**  
5. ➕ 在隧道详情页点击 **`已发布应用程序路由` → `添加已发布应用程序路由`**  
6. 🌍 配置 **主机名** 和 **服务**：  
   - 示例：`sub.你的域名.com/path`  
     - `sub` → (可选) 子域  
     - `你的域名` → 域名  
     - `path` → (可选) 路径  
   - 服务类型 → 选择 **`http`**  
   - URL → 输入 `localhost:8199` 或 `localhost:8299`  

---

### 📒 需添加的路由条目

| 🌐 外网访问地址                  | 🎯 本地服务地址      |
|----------------------------------|----------------------|
| `sub.你的域名.com/admin`         | `localhost:8199`     |
| `sub.你的域名.com/static`        | `localhost:8199`     |
| `sub.你的域名.com/api`           | `localhost:8199`     |
| `sub.你的域名.com/share`         | `localhost:8299`     |
| `sub.你的域名.com/sub-store-path`| `localhost:8299`     |

### 🎉 使用方法

打开浏览器访问 👉 sub.你的域名.com/admin -> 输入 apiKey -> 🎇 Enjoy!

## 🛠️ 部署与使用

> 首次运行会在当前目录生成默认配置文件。

### 🪜 优化系统代理和github代理设置（可选）

> 新增: 自动检测并设置系统代理;自动检测筛选github代理并设置

```yaml
# 新增设置项
# 优先级 1.system-proxy;2.github-proxy;3.ghproxy-group
# 即使未设置,也会检测常见端口(v2ray\clash)的系统代理自动设置

# 系统代理设置: 适用于拉取代理、消息推送、文件上传等等。
# 写法跟环境变量一样，修改需重启生效
# system-proxy: "http://username:password@192.168.1.1:7890"
# system-proxy: "socks5://username:password@192.168.1.1:7890"
system-proxy: ""
# Github 代理：获取订阅使用
# github-proxy: "https://ghfast.top/"
github-proxy: ""
# GitHub 代理列表：程序会自动筛选可用的 GitHub 代理
ghproxy-group:
# - https://ghp.yeye.f5.si/
# - https://git.llvho.com/
# - https://hub.885666.xyz/
# - https://p.jackyu.cn/
# - https://github.cnxiaobai.com/
```

<details>
  <summary>展开查看</summary>

如果拉取非Github订阅速度慢，可使用通用的 HTTP_PROXY HTTPS_PROXY 环境变量加快速度；此变量不会影响节点测试速度

```bash
# HTTP 代理示例
export HTTP_PROXY=http://username:password@192.168.1.1:7890
export HTTPS_PROXY=http://username:password@192.168.1.1:7890

# SOCKS5 代理示例
export HTTP_PROXY=socks5://username:password@192.168.1.1:7890
export HTTPS_PROXY=socks5://username:password@192.168.1.1:7890

# SOCKS5H 代理示例
export HTTP_PROXY=socks5h://username:password@192.168.1.1:7890
export HTTPS_PROXY=socks5h://username:password@192.168.1.1:7890
```

如果想加速github的链接，可使用网上公开的github proxy，或者使用下方自建测速地址处的worker.js自建加速

```yaml
# Github Proxy，获取订阅使用，结尾要带的 /
# github-proxy: "https://ghfast.top/"
github-proxy: "https://custom-domain/raw/"
```

</details>

### 🌐 自建测速地址（可选）

<details>
  <summary>展开查看</summary>

> **⚠️ 注意：** 避免使用 Speedtest 或 Cloudflare 下载链接，因为部分节点会屏蔽测速网站。

1. 将 [worker.js](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/cloudflare/worker.js) 部署到 Cloudflare Workers。
2. 绑定自定义域名（避免被节点屏蔽）。
3. 在配置文件中设置 `speed-test-url` 为你的 Workers 地址：

```yaml
# 100MB
speed-test-url: https://custom-domain/speedtest?bytes=104857600
# 1GB
speed-test-url: https://custom-domain/speedtest?bytes=1073741824
```

</details>

### 🐳 Docker 运行

> **⚠️ 注意：**  
>
> - 限制内存请使用 `--memory="500m"`。  
> - 可通过环境变量 `API_KEY` 设置 Web 控制面板的 API Key。

```bash
# 基础运行
docker run -d \
  --name subs-check \
  -p 8299:8299 \
  -p 8199:8199 \
  -v ./config:/app/config \
  -v ./output:/app/output \
  --restart always \
  ghcr.io/sinspired/subs-check:latest

# 使用代理运行
docker run -d \
  --name subs-check \
  -p 8299:8299 \
  -p 8199:8199 \
  -e HTTP_PROXY=http://192.168.1.1:7890 \
  -e HTTPS_PROXY=http://192.168.1.1:7890 \
  -v ./config:/app/config \
  -v ./output:/app/output \
  --restart always \
  ghcr.io/sinspired/subs-check:latest
```

### 📜 Docker-Compose

```yaml
version: "3"
services:
  subs-check:
    image: ghcr.io/sinspired/subs-check:latest
    container_name: subs-check
    volumes:
      - ./config:/app/config
      - ./output:/app/output
    ports:
      - "8299:8299"
      - "8199:8199"
    environment:
      - TZ=Asia/Shanghai
      # - HTTP_PROXY=http://192.168.1.1:7890
      # - HTTPS_PROXY=http://192.168.1.1:7890
      # - API_KEY=subs-check
    restart: always
    network_mode: bridge
```

### 📦 二进制文件运行

下载 [Releases](https://github.com/sinspired/subs-check/releases) 中适合的版本，解压后直接运行即可。

### 🖥️ 源码运行

```bash
go run . -f ./config/config.yaml
```

## 🔔 通知渠道配置（可选）

<details>
  <summary>展开查看</summary>

> **📦 支持 100+ 通知渠道**，通过 [Apprise](https://github.com/caronc/apprise) 发送通知。

### 🌐 Vercel 部署

1. 点击[**此处**](https://vercel.com/new/clone?repository-url=https://github.com/sinspired/apprise_vercel)部署 Apprise。
2. 部署后获取 API 链接，如 `https://projectName.vercel.app/notify`。
3. 建议为 Vercel 项目设置自定义域名（国内访问 Vercel 可能受限）。

### 🐳 Docker 部署

> **⚠️ 注意：** 不支持 arm/v7。

```bash
# 基础运行
docker run --name apprise -p 8000:8000 --restart always -d caronc/apprise:latest

# 使用代理运行
docker run --name apprise \
  -p 8000:8000 \
  -e HTTP_PROXY=http://192.168.1.1:7890 \
  -e HTTPS_PROXY=http://192.168.1.1:7890 \
  --restart always \
  -d caronc/apprise:latest
```

### 📝 配置文件中配置通知

```yaml
# 填写搭建的apprise API server 地址
# https://notify.xxxx.us.kg/notify
apprise-api-server: ""
# 填写通知目标
# 支持100+ 个通知渠道，详细格式请参照 https://github.com/caronc/apprise
recipient-url: 
  # telegram格式：tgram://{bot_token}/{chat_id}
  # - tgram://xxxxxx/-1002149239223
  # 钉钉格式：dingtalk://{Secret}@{ApiKey}
  # - dingtalk://xxxxxx@xxxxxxx
# 自定义通知标题
notify-title: "🔔 节点状态更新"
```

</details>

## 💾 保存方法配置

> **⚠️ 注意：** 选择保存方法时，请更改 `save-method` 配置。

- **本地保存**：保存到 `./output` 文件夹。
- **R2**：保存到 Cloudflare R2 [配置方法](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/r2.md)。
- **Gist**：保存到 GitHub Gist [配置方法](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/gist.md)。
- **WebDAV**：保存到 WebDAV 服务器 [配置方法](https://raw.githubusercontent.com/sinspired/subs-check/main/doc/webdav.md)。
- **S3**：保存到 S3 对象存储。

## 📲 订阅使用方法

> **💡 提示：** 内置 Sub-Store，可生成多种订阅格式；高级玩家可DIY很多功能

**🚀 通用订阅**

```bash
# 通用订阅
http://127.0.0.1:8299/download/sub

# URI 订阅
http://127.0.0.1:8299/download/sub?target=URI

# Mihomo/ClashMeta
http://127.0.0.1:8299/download/sub?target=ClashMeta

# Clash
http://127.0.0.1:8299/download/sub?target=Clash

# V2Ray
http://127.0.0.1:8299/download/sub?target=V2Ray

# ShadowRocket
http://127.0.0.1:8299/download/sub?target=ShadowRocket

# Quantumult
http://127.0.0.1:8299/download/sub?target=QX

# Sing-Box
http://127.0.0.1:8299/download/sub?target=sing-box

# Surge
http://127.0.0.1:8299/download/sub?target=Surge

# Surfboard
http://127.0.0.1:8299/download/sub?target=Surfboard
```

**🚀 Mihomo/Clash 订阅（带规则）：**
> 默认使用 `https://raw.githubusercontent.com/sinspired/override-hub/refs/heads/main/yaml/ACL4SSR_Online_Full.yaml` 覆写  
可在配置中更改 `mihomo-overwrite-url`。

```bash
http://127.0.0.1:8299/api/file/mihomo

# 如果设置了(建议设置) sub-store-path: "/path"
http://127.0.0.1:8299/path/api/file/mihomo
```

## 🌐 内置端口说明
>
> subs-check本身会在测试完后保存三个文件到output目录中；output目录中的所有文件会被8199端口提供文件服务

| 服务地址                                 | 格式说明                       | 来源说明                      |
| ---------------------------------------- | ------------------------------ | ----------------------------- |
| `http://127.0.0.1:8199/sub/all.yaml`     | Clash 格式节点                 | 由subs-check直接生成          |
| `http://127.0.0.1:8199/sub/mihomo.yaml`  | 带分流规则的 Mihomo/Clash 订阅 | 从上方sub-store转换下载后提供 |
| `http://127.0.0.1:8199/sub/base64.txt`   | Base64 格式订阅                | 从上方sub-store转换下载后提供 |
| `http://127.0.0.1:8199/sub/history.yaml` | Clash 格式节点                 | 历次检测可用节点              |

## 🗺️ 架构图

<details>
  <summary>展开查看</summary>

```mermaid
graph TD
    A[订阅链接] -->|获取订阅链接| B[subs-check]
    subgraph subs-check 处理流程
        B -->|转成 YAML 格式| B1[节点去重]
        B1 -->|去除冗余节点| B2[测活]
        B2 -->|节点可用| B3[测速]
        B2 -->|节点不可用| X[丢弃]
        B3 -->|测速达标| B4[流媒体测试]
        B3 -->|测速不达标| X[丢弃]
        B4 -->|解锁检测| B5[生成 all.yaml]
    end
    B5 -->|保存到 output 目录| C[output 目录]
    B5 -->|上传 all.yaml| D[sub-store]
    C -->|保存到各位置| H1[R2/Gist/WebDAV/S3]
    H1 -->|存储完成| H2[发送消息通知]
    D -->|提供订阅转换服务| E[sub-store 转换服务]
    subgraph sub-store 独立功能
        E -->|生成配置文件| E1[mihomo.yaml, base64.txt]
        E -->|其他格式转换| E2[Clash, V2Ray, ShadowRocket 等]
        E -->|订阅分享| E3[分享订阅链接]
    end
    E1 -->|保存到 output 目录| C
    C -->|文件服务| F[8199 端口: /sub]
    B -->|Web 管理| G[8199 端口: /admin]
```

</details>

## 🙏 鸣谢

[beck-8](https://github.com/beck-8)、[cmliu](https://github.com/cmliu)、[Sub-Store](https://github.com/sub-store-org/Sub-Store)、[bestruirui](https://github.com/bestruirui/BestSub)

## ⭐ Star History

[![Stargazers over time](https://starchart.cc/sinspired/subs-check.svg?variant=adaptive)](https://starchart.cc/sinspired/subs-check)

## ⚖️ 免责声明

本工具仅供学习和研究使用，使用者应自行承担风险并遵守相关法律法规。
