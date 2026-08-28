# nft_po0

`nft_po0` 是一个面向 Linux 服务器的交互式 nftables IPv4 端口中转与防火墙管理脚本。

当前版本：`3.0.0`

## 主要功能

- TCP、UDP 或 TCP+UDP 的 IPv4 DNAT/SNAT 中转。
- 为每个目标地址独立检测出口接口和 SNAT 源地址。
- 支持来源 IPv4/CIDR 白名单。
- 支持关闭、自动或固定 TCP MSS。
- 提供安全接管和 NAT 共存两种防火墙模式。
- 检查 SSH、本机监听端口和转发端口冲突。
- 使用独立的 nftables 表和 systemd 服务持久化规则。
- 应用前备份并执行 nftables 语法检查。
- 提供 120 秒自动回滚保护，降低远程 SSH 失联风险。

## 工作模式

### 安全接管模式（takeover）

脚本管理 NAT、`input` 和 `forward`，后两者默认策略为 `drop`。它会自动放行 SSH，并允许用户登记其他本机服务端口。

该模式不适合正在使用 UFW、firewalld、Docker 或 containerd 的主机；脚本会在应用前检查并拒绝高风险组合。

### NAT 共存模式（coexist）

脚本只管理 DNAT、SNAT 和可选 MSS，不修改 `input` 或 `forward`。已有防火墙必须另行允许 DNAT 后的转发流量。

## 系统要求

- 使用 systemd 的 Linux 发行版。
- root 权限。
- Bash、nftables、iproute2 和 util-linux。
- 目前仅支持 IPv4 中转。

脚本支持使用 `apt-get`、`dnf` 或 `yum` 安装运行依赖。

## 使用方法

```bash
# 查看帮助
bash nft_po0.sh --help

# 安装依赖
sudo bash nft_po0.sh --install-deps

# 进入交互管理菜单
sudo bash nft_po0.sh

# 查看状态、路由和规则计数器
sudo bash nft_po0.sh --status

# 从历史备份恢复
sudo bash nft_po0.sh --rollback
```

首次使用时，脚本会要求选择工作模式。添加或删除规则只会改变待应用列表，必须在菜单中选择“应用并保存”才会生效。

应用时需要输入 `APPLY`，然后应立即测试 SSH 和转发连接，并在倒计时结束前输入 `KEEP`。未确认或加载失败时，脚本会尝试恢复应用前的配置。

## 配置和备份位置

应用后主要使用以下路径：

```text
/etc/po0-relay/
/etc/sysctl.d/99-po0-relay.conf
/usr/local/sbin/po0-relay-loader
/etc/systemd/system/po0-relay.service
/root/po0-relay-backups/
```

脚本维护的 nftables 表：

```text
ip   po0_relay_nat
inet po0_relay_filter
ip   po0_relay_mangle
```

## 安全提示

- 建议始终保留当前 SSH 会话，确认新连接正常后再输入 `KEEP`。
- 安全接管模式会对未登记的本机端口和新建转发流量执行默认拒绝。
- NAT 共存模式不能绕过已有防火墙的 `FORWARD` 丢弃规则。
- 出口地址或路由变化后，应重新应用配置，以刷新逐规则 SNAT 地址。
- 回滚会恢复备份时捕获的完整活动 ruleset，可能覆盖备份之后由其他程序添加的防火墙规则。

## 开发与检查

提交修改前至少运行 Bash 语法检查：

```bash
bash -n nft_po0.sh
```

建议同时使用 ShellCheck：

```bash
shellcheck nft_po0.sh
```

涉及规则生成的修改应在测试服务器或虚拟机上通过 `nft -c` 和实际连接测试验证，避免直接在唯一的远程入口主机上试验。

## 许可证

本项目目前未声明开源许可证。公开可见不等于授权复制、修改或再分发；如需开放使用，应由仓库所有者另行选择并添加许可证。
