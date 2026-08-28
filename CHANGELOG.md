# Changelog

本项目的重要变化记录在此文件中。

## [3.0.0] - 2026-08-27

### Added

- 每条转发规则独立检测出口接口和 SNAT 源地址。
- 安全接管与 NAT 共存两种运行模式。
- 来源 IPv4/CIDR 白名单。
- 可选的 TCP MSS 自动或固定值设置。
- 独立的 `po0_relay_*` nftables 表和 systemd 加载服务。
- 应用前备份、语法检查和限时自动回滚保护。
- v2 状态和配置迁移支持。

### Changed

- `forward` 和 `postrouting` 使用 `ct status dnat` 限定实际 DNAT 连接。
- 中转端口仅经过 `prerouting`/`forward`，不作为本机服务端口加入 `input`。
