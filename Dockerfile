FROM golang:alpine AS builder
WORKDIR /app
COPY . .
ARG GITHUB_SHA
ARG VERSION
RUN apk add --no-cache nodejs zstd && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
        "x86_64") zstd -f /usr/bin/node -o assets/node_linux_amd64.zst ;; \
        "aarch64") zstd -f /usr/bin/node -o assets/node_linux_arm64.zst ;; \
        "armv7l") zstd -f /usr/bin/node -o assets/node_linux_armv7.zst ;; \
        *) echo "不支持的架构: $ARCH" && exit 1 ;; \
    esac
RUN echo "Building commit: ${GITHUB_SHA:0:7}" && \
    go mod tidy && \
    go build -ldflags="-s -w -X main.Version=${VERSION} -X main.CurrentCommit=${GITHUB_SHA:0:7}" -trimpath -o subs-check .

FROM alpine
ENV TZ=Asia/Shanghai
RUN apk add --no-cache alpine-conf ca-certificates nodejs &&\
    /usr/sbin/setup-timezone -z Asia/Shanghai && \
    apk del alpine-conf && \
    rm -rf /var/cache/apk/* && \
    rm -rf /usr/bin/node
COPY --from=builder /app/subs-check /app/subs-check
CMD /app/subs-check
EXPOSE 8199
EXPOSE 8299