# 共享本地开发环境给测试人员

场景：你在本地开发 `D:\highgo_projects\higobase_platform`（Windows，内网 / NAT 后面），测试人员在外网。c 是公网服务器。通过 cproxy 把本地 Vite 开发站点以 `http://<c>:8080/higobase-admin/` 暴露出去，**不暴露你的机器，也不需要在路由器上做端口映射**。

```
测试人员浏览器 ──HTTP──▶ c:8080/higobase-admin/ ──反向代理──▶ 隧道 ──▶ 你的电脑 agent ──▶ 127.0.0.1:5174 (Vite)
```

## 1. 前提

- 你的电脑能出站访问 `c:8080`（普通上网即可）。
- c 上已放行 `8080/tcp`，其余端口不用开。
- 本地已安装 Node 与项目依赖（`frontend/node_modules` 存在）。

## 2. c：部署 server（只做一次）

```bash
mkdir -p /etc/cproxy/certs
cproxy gen-token > /etc/cproxy/token && chmod 600 /etc/cproxy/token
```

`/etc/cproxy/server.json`：

```json
{
  "public_listen": "0.0.0.0:8080",
  "admin_listen": "127.0.0.1:7002",
  "token_file": "/etc/cproxy/token",
  "tunnel_tls": {
    "enabled": true,
    "cert_file": "/etc/cproxy/certs/tunnel.crt",
    "key_file": "/etc/cproxy/certs/tunnel.key",
    "auto_generate": true,
    "public_host": "203.0.113.10"
  },
  "log_level": "info",
  "log_format": "json"
}
```

```bash
cproxy server -f /etc/cproxy/server.json     # 前台试跑没问题后交给 systemd
cproxy fingerprint -c /etc/cproxy/certs/tunnel.crt
# sha256:xxxxxxxx...    <- 复制给本地 agent 用
```

systemd 见 `deploy/systemd/cproxy-server.service`。c 上 `ss -lntp | grep cproxy` 应只有 `0.0.0.0:8080` 和 `127.0.0.1:7002`。

## 3. 本地：启动一个带 base path 的开发站点

项目 `vite.config.ts` 里 `base` 只在 production 下是 `/higobase-admin/`，开发模式是 `/`。**不要改配置文件**，用命令行覆盖，单开一个“共享用”的实例：

```powershell
cd D:\highgo_projects\higobase_platform\frontend
npm run dev -- --base=/higobase-admin/ --port 5174 --strictPort
```

打开 `http://localhost:5174/higobase-admin/` 自测，页面里的资源路径应类似 `/higobase-admin/src/main.ts`。原来的 `npm run dev`（5173，根路径）继续用于你自己的开发，两者互不影响。

> 为什么要 base：代理按路径前缀路由，页面里的绝对路径（`/src/main.ts`、`/@vite/client`）必须自带 `/higobase-admin`，否则浏览器请求 `/src/main.ts` 会命中代理的 404。

默认情况下 Vite 会把 `/higobase-admin/api` 转发到 `http://localhost:6789`，测试人员访问时，**你本机要把 6789 的后端也跑起来**，否则页面接口会 502/404。

## 4. 本地：启动 agent

准备 `D:\highgo_projects\go_proxy\agent.json`（token 与 c 一致，指纹用第 2 步的输出）：

```json
{
  "server": "203.0.113.10:8080",
  "agent_id": "dev-<你的名字>",
  "token_file": "C:\\highgo_projects\\go_proxy\\token",
  "tunnel_tls": { "fingerprint": "sha256:REPLACE_ME" },
  "services": [
    {
      "name": "higobase-dev",
      "path_prefix": "/higobase-admin",
      "target": "127.0.0.1:5174",
      "strip_prefix": false
    }
  ],
  "log_level": "info",
  "log_format": "text"
}
```

```powershell
# token 文件：内容为 c 上 /etc/cproxy/token 的同一串
Set-Content -Path D:\highgo_projects\go_proxy\token -Value 'REPLACE_WITH_TOKEN' -NoNewline

D:\highgo_projects\go_proxy\bin\cproxy.exe check -f D:\highgo_projects\go_proxy\agent.json
D:\highgo_projects\go_proxy\bin\cproxy.exe agent -f D:\highgo_projects\go_proxy\agent.json
```

日志出现 `control tunnel established` 和 `service registered` 即成功。

## 4.1 用本地管理界面改路由（推荐）

浏览器打开 **<http://127.0.0.1:7100/>**：

- 顶部显示服务器地址、agent 名、会话 ID、配置文件路径和连接状态；
- 表格里可以直接改服务名、公开路径前缀、本地目标、是否去前缀，支持新增和删除；
- 点“保存并生效”后：
  - 立即在现有隧道上重新注册，公网路由马上更新（旧路由被删除后会变成 404）；
  - 改动本地目标时，旧的空闲连接会被丢弃，下一次请求就走到新目标；
  - 新路由写回 `agent.json`，重启 agent 后保持；
- 前缀重叠、非法路径、保留路径 `/_cproxy`、非法 `host:port` 会直接报错，原路由不受影响；
- “重连”按钮用于强制重建到 c 的控制连接。

只想临时换个端口或路径，不用再改 JSON、也不用重启 agent。若需关闭界面，把 `agent.json` 的 `ui_listen` 改成 `"off"`；改成 `0.0.0.0:7100` 会允许同网段访问，请自行评估。

## 5. 测试人员访问

```
http://203.0.113.10:8080/higobase-admin/
```

所有测试人员看到的都是**你本机当前运行的代码**，你保存文件后页面刷新即可看到最新效果（Vite HMR 也通过代理可用）。

## 6. 验证清单

在 c 上：

```bash
curl -s http://127.0.0.1:7002/status | jq '.services'
# online 应为 true，requests 随访问增长
```

在本地模拟测试人员（自测同样有效）：

```powershell
curl.exe -sS -o NUL -w "%{http_code} %{content_type}`n" http://203.0.113.10:8080/higobase-admin/
curl.exe -sS -o NUL -w "%{http_code} %{content_type}`n" http://203.0.113.10:8080/higobase-admin/src/main.ts
```

预期 `200 text/html` 和 `200 text/javascript`。代理会注入 `X-Request-ID`，返回头里能看到。

## 7. 排障

| 现象 | 原因与处理 |
|---|---|
| 测试人员 404 | 路径前缀不匹配。前缀按路径段匹配，`/higobase-adminx` 不会命中；确认访问的是 `/higobase-admin/` |
| 测试人员 503 | agent 没连上：检查本地 agent 进程、token 是否与 c 一致、公司网络是否允许出站 8080 |
| 测试人员 502 | 本地 Vite 没起或端口不是 5174，或你改了 `target` |
| 页面 200 但白屏、控制台 `/src/main.ts` 404 | 开发站点没带 base，用第 3 步的 `--base=/higobase-admin/` 启动 |
| 接口 404/502 | 本地 6789 后端没起，或 Vite 的 proxy 配置路径与实际不符 |
| HMR 断开、控制台 WebSocket 报错 | 协议升级已支持；检查是否有中间设备拦截 `Upgrade`。HMR 断开不影响页面浏览，刷新即可 |
| `fingerprint mismatch` | c 重新生成过证书，重新执行 `cproxy fingerprint` 并更新本地配置 |
| `http://127.0.0.1:7100/` 打不开 | agent 没起，或 `ui_listen` 被设为 `"off"`，或端口被占用（改 `ui_listen` 重启 agent） |
| 界面点保存报“尚未连接” | agent 与 c 的隧道断开了：看界面右上角状态和“上次错误”，网络恢复后会自动重连 |
| 保存后访问仍是旧页面 | 可能命中了旧隧道连接，刷新一次；确认界面里“本地目标”已经是新端口 |
| 想临时下线 | 停掉本地 agent，测试人员立即得到 503；你的开发环境不受影响 |

## 8. 收工

- 停止本地 agent 即可关闭对外访问，c 上的 8080 继续留给下次共享。
- 换路径或换目标端口：直接在管理界面改并保存，或者改 `agent.json` 后重启 agent。
- 需要长期共享时，把 agent 注册为 Windows 计划任务或服务（`nssm`、`sc.exe` 均可），命令与第 4 步一致。