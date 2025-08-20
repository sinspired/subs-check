# 安卓手机运行subs-check教程
> 使用Termux

## 前置条件
- 确保网络连接正常
- 建议使用 Android 7.0 及以上系统
- 你有一定的技术/折腾能力，小白误入

## 安装依赖

```bash
pkg update && pkg add nodejs ca-certificates which proot termux-exec -y
```

## 下载解压程序
忽略，自行解决，不会就别玩

## 切换环境
> 每次打开终端运行subs-check都需要切换一下
```bash
# 目的是为了让subs-check有个完整的Linux环境
termux-chroot

# 如遇到DNS问题，请自行更改/etc/resolv.conf
echo "nameserver 223.5.5.5" > /etc/resolv.conf
```
## 设置环境变量
```bash
# 临时设置环境变量
# 无Root权限的手机设置,有Root权限应该授权后无需设置
export SSL_CERT_FILE="/data/data/com.termux/files/usr/etc/tls/cert.pem"

export NODEBIN_PATH="$(which node)"
```
```bash
# 设置持久环境变量，重新打开终端无需再次设置
echo 'export SSL_CERT_FILE="/data/data/com.termux/files/usr/etc/tls/cert.pem"' >> ~/.bashrc
echo 'export NODEBIN_PATH="$(which node)"' >> ~/.bashrc
source ~/.bashrc
```

## 运行程序
```bash
./subs-check
```

## 常见问题
1. 如果遇到证书错误，确保已正确设置 `SSL_CERT_FILE`
2. 如果提示权限不足，确保已执行 `chmod 755 subs-check`
3. 如果提示找不到 node，确保已正确设置 `NODEBIN_PATH`