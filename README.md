# tlsocks5

TLS SOCKS5 服务，通过配置的上游 SOCKS5 转发 TCP 和 UDP。

## Clash / Mihomo

```yaml
proxies:
  - name: tlsocks5
    type: socks5
    server: proxy.example.com
    port: 1080
    username: user
    password: your-password
    tls: true
    udp: true
```

替换服务器、端口及密码，服务器证书须通过客户端校验。

## UDP 部署条件

- 上游 `trans.connect_ips` / `trans.connect_ports` 的第一个 SOCKS5 服务必须支持无认证的 UDP ASSOCIATE。UDP 与 TCP 使用相同上游；上游拒绝 UDP 时会向客户端返回失败。
- 每个 UDP 会话在服务端控制连接所在本地 IP 上分配一个系统临时 UDP 端口。安全组和主机防火墙必须允许客户端访问该系统的临时 UDP 端口范围，也必须允许服务器与上游 UDP 中继通信。仅开放 TCP 监听端口不够。
- 当前适用于公网 IP 直接配置在服务器网卡的部署。服务器位于 NAT 后时，返回的本地中继地址/临时端口可能无法从公网访问；当前未实现公网地址公告、固定中继端口或 NAT 端口映射。
- 标准 SOCKS5 UDP 数据通过独立 UDP 套接字传送，**不受 TCP 控制连接上的 TLS 加密保护**。
- 支持 IPv4、IPv6、域名 UDP 头。按 RFC 1928 丢弃分片（FRAG 非零）及无效报文；只接受控制连接客户端 IP，并在首个有效报文后锁定客户端源端口。
- 客户端或上游控制连接关闭、或达到 `base.idle_timeout` 后，关闭关联的 UDP 套接字。UDP 会话也受现有全局和单 IP 连接上限约束。

## 空闲断开

TCP 和 UDP 在两个方向均无业务数据达到超时时间后断开，释放连接名额。
`base.idle_timeout` 单位为秒；未配置时使用 `base.time_out`，不再默认等待 1800 秒。
`time_out` 必须为正数。`idle_timeout` 为零或负数时也回退到 `time_out`。
TCP keepalive 探测不会重置业务空闲计时；任意方向仍在传输业务数据时继续保持连接。

例如以下配置会在连续 60 秒没有业务数据时断开 TCP/UDP 会话：

```ini
[base]
time_out=60
idle_timeout=60
```

## 验证

`cargo test` 包含 UDP 报文验证、本地模拟上游的双向 UDP 转发及控制连接关闭后的清理测试。真实 Clash 和远程上游的连通性仍需在部署环境验证。

## Windows 本机编译 Linux musl

本机已安装 Windows 版 [Matrix3600/musl-cross](https://github.com/Matrix3600/musl-cross/releases/tag/win-x64-20261015)
GCC 工具链到 `.tools/musl-gcc/x86_64-unknown-linux-musl/`，并通过本地 `.cargo/config.toml`
配置链接器、CC 和 AR。这两个路径已忽略提交，其他机器需要另行安装配置。
该工具链的 `libwinpthread-1.dll` 原本只放在 `bin`；本机已将同一份 DLL
复制到 GCC 子程序目录，以便不修改全局 PATH 也能调用 `cc1`、汇编器和链接器。

在项目根目录运行，不需要 Zig，也不需要修改全局 PATH：

```powershell
cargo build --release --locked --target x86_64-unknown-linux-musl
```

产物：`target/x86_64-unknown-linux-musl/release/tlssocks5`。
工具链和本地配置不在 `target` 内，`cargo clean` 后仍可使用。
