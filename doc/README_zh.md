# 使用方法

> ⚠️ **重要提示**  
> 本项目正在积极开发中。  
> 配置文件可能会频繁更改。  
> 请密切关注文档更新。


### 直接运行

1. 根据自己系统选择 [release](https://github.com/bestruirui/BestSub/releases) 中的文件
2. 下载[config.example.yaml](https://raw.githubusercontent.com/bestruirui/BestSub/master/doc/config.example.yaml) 和 [rename.yaml](https://raw.githubusercontent.com/bestruirui/BestSub/master/doc/rename.yaml) 文件 到 `config` 文件夹中
3. 参考[配置文件说明](./config_zh.md) 修改配置文件后，重命名为 `config.yaml`
4. 运行即可

### Docker

```bash
mkdir -p /path/to/config
````

```bash
docker run -itd \
    --name bestsub \
    -p 8080:8080 \
    -v /path/to/config:/app/config \
    -v /path/to/output:/app/output \
    --restart=always \
    ghcr.io/bestruirui/bestsub
```

### 源码直接运行

```bash
go run main.go -f /path/to/config.yaml -r /path/to/rename.yaml
```


### 自建测速地址

> (可选操作) 由于部分节点屏蔽常见的测速地址，所以需要自建测速地址

- 将 [worker](./cloudflare/worker.js) 部署到 Cloudflare Workers

- 将 `speed-test-url` 配置为你的 worker 地址

```yaml
speed-test-url: https://your-worker-url/speedtest?bytes=1000000
```

### 保存方法配置

- 📁 本地保存：将结果保存到本地，默认保存到可执行文件目录下的 output 文件夹
- ☁️ r2：将结果保存到 Cloudflare R2 存储桶 [配置方法](./r2_zh.md)
- 💾 gist：将结果保存到 GitHub Gist [配置方法](./gist_zh.md)
- 🌐 webdav：将结果保存到 webdav 服务器 [配置方法](./webdav_zh.md)

### 订阅使用方法

推荐直接裸核运行 tun 模式

我自己写的Windows下的裸核运行应用 [minihomo](https://github.com/bestruirui/minihomo)

- 下载 [base.yaml](./base.yaml)
- 将文件中对应的链接改为自己的即可

例如:

```yaml
proxy-providers:
  ProviderALL:
    url: https:// # 将此处替换为自己的链接
    type: http
    interval: 600
    proxy: DIRECT
    health-check:
      enable: true
      url: http://www.google.com/generate_204
      interval: 60
    path: ./proxy_provider/ALL.yaml
```

如果使用 `local` 保存方式

```yaml
proxy-providers:
  ProviderALL:
    file: /path/to/all.yaml
    type: file
```

### 自动更新订阅

实现检测完成后自动更新订阅

参考[配置文件说明](./config_zh.md#mihomo) 中的 `mihomo` 选项
