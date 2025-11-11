package platform

// SpeedTestURLs 测速专用URL列表（随机选择使用），所有文件>80MB，支持并发下载
var SpeedTestURLs = []string{
	// === 1. 专用速度测试服务器 (Global / Unspecified) ===
	// thinkbroadband (英国)
	"https://download.thinkbroadband.com/512MB.zip",     // 512MB ZIP
	"http://ipv4.download.thinkbroadband.com/512MB.zip", // 512MB ZIP
	// Tele2 (欧洲)
	"http://speedtest.tele2.net/1GB.zip", // 1GB ZIP
	// CacheFly (全球 CDN)
	"https://cachefly.cachefly.net/300mb.test", // 300mb Test File

	// === 2. 专用速度测试服务器 (Regional - Asia) ===
	// Datapacket/CDN77 (香港)
	"http://hkg.download.datapacket.com/100mb.bin",   // 100MB
	"http://hkg.download.datapacket.com/1000mb.bin",  // 1GB
	"http://hkg.download.datapacket.com/10000mb.bin", // 10GB
	// Datapacket/CDN77 (新加坡)
	"http://sgp.download.datapacket.com/100mb.bin",   // 100MB
	"http://sgp.download.datapacket.com/1000mb.bin",  // 1GB
	"http://sgp.download.datapacket.com/10000mb.bin", // 10GB
	// Datapacket/CDN77 (东京)
	"http://tyo.download.datapacket.com/100mb.bin",   // 100MB
	"http://tyo.download.datapacket.com/1000mb.bin",  // 1GB
	"http://tyo.download.datapacket.com/10000mb.bin", // 10GB
	// OVH (新加坡)
	"https://sgp.proof.ovh.net/files/100Mb.dat", // 100MB
	"https://sgp.proof.ovh.net/files/1Gb.dat",   // 1GB
	"https://sgp.proof.ovh.net/files/10Gb.dat",  // 10GB
	// Vultr (新加坡)
	"https://sgp-ping.vultr.com/vultr.com.100MB.bin",  // 100MB
	"https://sgp-ping.vultr.com/vultr.com.1000MB.bin", // 1GB
	// Vultr (东京)
	"https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin",  // 100MB
	"https://hnd-jp-ping.vultr.com/vultr.com.1000MB.bin", // 1GB
	// DigitalOcean (新加坡 SGP1)
	"http://speedtest-sgp1.digitalocean.com/1000mb.test", // 1GB

	// === 3. 专用速度测试服务器 (Regional - Europe) ===
	// OVH (Generic)
	"https://proof.ovh.net/files/100Mb.dat", // 100Mb
	"http://proof.ovh.net/files/1Gb.dat",    // 1GB
	"http://proof.ovh.net/files/10Gb.dat",   // 10GB
	// DigitalOcean (伦敦 LON1)
	"http://speedtest-lon1.digitalocean.com/100mb.test", // 100mb
	// Hetzner (Nuremberg, 德国)
	"https://nbg1-speed.hetzner.com/100MB.bin", // 100MB
	"https://nbg1-speed.hetzner.com/1GB.bin",   // 1GB
	"https://nbg1-speed.hetzner.com/10GB.bin",  // 10GB
	// Vultr (Frankfurt, 德国)
	"https://fra-de-ping.vultr.com/vultr.com.100MB.bin",  // 100MB
	"https://fra-de-ping.vultr.com/vultr.com.1000MB.bin", // 1GB
	// Hivelocity (Frankfurt, 德国)
	"https://speedtest.fra1.hivelocity.net/10GiB.file", // 10GB
	// Datapacket/CDN77 (巴黎)
	"http://par.download.datapacket.com/100mb.bin",   // 100MB
	"http://par.download.datapacket.com/1000mb.bin",  // 1GB
	"http://par.download.datapacket.com/10000mb.bin", // 10GB
	// OVH (Gravelines, 法国)
	"https://gra.proof.ovh.net/files/100Mb.dat", // 100MB
	"https://gra.proof.ovh.net/files/1Gb.dat",   // 1GB
	"https://gra.proof.ovh.net/files/10Gb.dat",  // 10GB

	// === 4. 专用速度测试服务器 (Regional - North America) ===
	// Hetzner (Ashburn, VA, US East)
	"https://ash-speed.hetzner.com/1GB.bin",  // 1GB
	"https://ash-speed.hetzner.com/10GB.bin", // 10GB
	// Linode/Akamai (Fremont, CA, US West)
	"http://speedtest.fremont.linode.com/1000MB-fremont.bin", // 1GB
	// DigitalOcean (New York NYC1)
	"http://speedtest-nyc1.digitalocean.com/1000mb.test", // 1GB
	// Datapacket/CDN77 (Los Angeles, US West)
	"http://lax.download.datapacket.com/100mb.bin",   // 100MB
	"http://lax.download.datapacket.com/1000mb.bin",  // 1GB
	"http://lax.download.datapacket.com/10000mb.bin", // 10GB
	// OVH (Hillsboro, OR, US West)
	"https://hil.proof.ovh.us/files/100Mb.dat", // 100MB
	"https://hil.proof.ovh.us/files/1Gb.dat",   // 1GB
	"https://hil.proof.ovh.us/files/10Gb.dat",  // 10GB
	// Vultr (Los Angeles, US West)
	"https://lax-ca-us-ping.vultr.com/vultr.com.100MB.bin",  // 100MB
	"https://lax-ca-us-ping.vultr.com/vultr.com.1000MB.bin", // 1GB
	// Hetzner (Hillsboro, OR, US West)
	"https://hil-speed.hetzner.com/10GB.bin", // 10GB
	// Datapacket/CDN77 (Ashburn, VA, US East)
	"http://ash.download.datapacket.com/100mb.bin",   // 100MB
	"http://ash.download.datapacket.com/1000mb.bin",  // 1GB
	"http://ash.download.datapacket.com/10000mb.bin", // 10GB
	// OVH (Vint Hill, VA, US East)
	"https://vin.proof.ovh.us/files/100Mb.dat", // 100MB
	"https://vin.proof.ovh.us/files/1Gb.dat",   // 1GB
	"https://vin.proof.ovh.us/files/10Gb.dat",  // 10GB
	// Vultr (New Jersey, US East)
	"https://nj-us-ping.vultr.com/vultr.com.100MB.bin",  // 100MB
	"https://nj-us-ping.vultr.com/vultr.com.1000MB.bin", // 1GB

	// === 5. 云服务商 & 大型 CDN ===
	// Apple (IPSW Restore File)
	"http://updates-http.cdn-apple.com/2019WinterFCS/fullrestores/041-39257/32129B6C-292C-11E9-9E72-4511412B0A59/iPhone_4.7_12.1.4_16D57_Restore.ipsw", // 3GB
	"https://updates.cdn-apple.com/2025FallFCS/fullrestores/089-12066/4F86CB11-E6FA-47CB-96A8-527A4CBD9273/iPhone18,3_26.1_23B85_Restore.ipsw",
	// Cloudflare Speed (可指定字节数)
	"https://speed.cloudflare.com/__down?bytes=1073741824", // 1GB (Cloudflare)
	"https://speed.cloudflare.com/__down?bytes=5368709120", // 5GB (Cloudflare)
	// AWS CLI
	"https://awscli.amazonaws.com/AWSCLIV2.msi", // ~110MB MSI
	// Google Chrome
	"https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe", // ~140MB EXE
	// Microsoft Edge
	"https://msedge.sf.microsoft.com/edge/v130.0.2840.99/EdgeSetup.exe", // ~160MB EXE
	// VS Code (Microsoft CDN) - 固定版本 1.102.0
	"https://update.code.visualstudio.com/1.102.0/win32-x64-user/stable", // ~120MB EXE
	// Microsoft Azure (Blob CDN)
	"https://azurespeedtest.blob.core.windows.net/files/1GB.dat", // 1GB (Azure CDN)
	"https://azurespeedtest.blob.core.windows.net/files/5GB.dat", // 5GB (Azure CDN)
	// Android Studio (Google CDN)
	"https://redirector.gvt1.com/edgedl/android/studio/install/2024.2.1.18/android-studio-2024.2.1.18-windows.exe", // ~1.2 GB

	// === 6. Linux ISO 镜像 ===
	"https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.2.0-amd64-netinst.iso",
	"https://releases.ubuntu.com/25.10/ubuntu-25.10-desktop-amd64.iso", // ~5.5GB ISO
	"https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/43.20251024.3.0/x86_64/fedora-coreos-43.20251024.3.0-live-iso.x86_64.iso",
	"https://mirror.rackspace.com/archlinux/iso/2025.11.01/archlinux-2025.11.01-x86_64.iso",                // ~950MB ISO
	"https://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso",              // ~4GB ISO
	"https://mirror.stream.centos.org/10-stream/BaseOS/x86_64/iso/CentOS-Stream-10-latest-x86_64-dvd1.iso", // ~8GB ISO
	"https://repo.almalinux.org/almalinux/10.0/isos/aarch64/AlmaLinux-10-latest-aarch64-boot.iso",          //800mb

	// === 7. 大型开源软件 & 驱动 ===
	"https://download.blender.org/release/Blender4.3/blender-4.3.0-linux-x64.tar.xz", // ~320MB TAR.XZ (Linux)
	"https://download.blender.org/release/Blender4.3/blender-4.3.0-windows-x64.zip",  // ~340MB ZIP (Windows)
	"https://static.rust-lang.org/dist/rust-1.83.0-x86_64-unknown-linux-gnu.tar.gz",  // ~260MB TAR.GZ
	"https://download.gimp.org/mirror/pub/gimp/v3.0/windows/gimp-3.0.0-setup.exe",    // ~250MB EXE
	"https://downloads.apache.org/hadoop/common/hadoop-3.4.0/hadoop-3.4.0.tar.gz",    // ~210MB TAR.GZ
	"https://downloads.apache.org/spark/spark-4.0.1/pyspark-4.0.1.tar.gz",
	"https://download.kde.org/stable/plasma/6.2.0/plasma-desktop-6.2.0.tar.xz",                                                // ~300MB TAR.XZ
	"https://desktop.docker.com/win/stable/amd64/Docker%20Desktop%20Installer.exe",                                            // ~550MB EXE
	"https://download-installer.cdn.mozilla.net/pub/firefox/releases/145.0/win64/en-US/Firefox%20Setup%20145.0.exe",           // ~110MB EXE
	"https://download-installer.cdn.mozilla.net/pub/firefox/releases/140.5.0esr/win64/en-US/Firefox%20Setup%20140.5.0esr.exe", // ~110MB EXE
	"https://nodejs.org/dist/v22.13.1/node-v22.13.1-x64.msi",                                                                  // ~100MB MSI
	"https://developer.download.nvidia.com/compute/cuda/12.5.1/local_installers/cuda_12.5.1_555.85_windows.exe",               // ~3.6 GB (Windows)
	"https://developer.download.nvidia.com/compute/cuda/12.5.1/local_installers/cuda_12.5.1_555.42.06_linux.run",              // ~2.9 GB (Linux)
	"https://mirror.marwan.ma/tdf/libreoffice/stable/7.6.0/deb/x86_64/LibreOffice_7.6.0_Linux_x86-64_deb.tar.gz",              // ~360MB (Windows MSI)
	// PostgreSQL
	"https://get.enterprisedb.com/postgresql/postgresql-16.3-1-windows-x64.exe", // ~380MB (Windows)
	// Elastic (Elasticsearch)
	"https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.15.0-linux-x86_64.tar.gz", // ~500MB

	// === 8. 大型科学数据 & 数据库 ===
	// Wikipedia (数据库转储)
	"https://dumps.wikimedia.org/enwiki/latest/enwiki-latest-pages-articles-multistream.xml.bz2", // ~20GB+ (实时更新)

	// === 9. github 发布文件 ===
	// OpenJDK (Eclipse Temurin)
	"https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz",                                             // ~450MB TAR.XZ
	"https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.1%2B8/OpenJDK25U-debugimage_aarch64_alpine-linux_hotspot_25.0.1_8.tar.gz", // ~190MB
	"https://github.com/VSCodium/vscodium/releases/download/1.103.25610/VSCodium-linux-x64-1.103.25610.tar.gz",
	"https://github.com/VSCodium/vscodium/releases/download/1.105.17075/VSCodium.arm64.1.105.17075.dmg",
	"https://github.com/AaronFeng753/Waifu2x-Extension-GUI/releases/download/v3.131.01/Waifu2x-Extension-GUI-v3.131.01-Win64.7z",
	"https://github.com/2dust/v2rayN/releases/download/7.16.2/v2rayN-windows-64-SelfContained.zip",
	"https://github.com/PowerShell/PowerShell/releases/download/v7.5.4/PowerShell-7.5.4.msixbundle",
	"https://github.com/pytorch/pytorch/releases/download/v2.9.1/pytorch-v2.9.1.tar.gz",
	"https://github.com/mihomo-party-org/clash-party/releases/download/v1.8.8/mihomo-party-windows-1.8.8-x64-portable.7z",
}
