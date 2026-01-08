# 🚀 Kata-Node 一键部署 (防风控版)

本脚本用于在 Node.js 环境（如 PaaS 平台）快速部署伪装版节点服务。

## ✨ 特点
* **完全伪装**：进程名、文件名均伪装为普通 Web 服务，绕过关键词检测。
* **极简部署**：自动处理依赖、证书生成与配置。
* **隐私保护**：控制台不直接输出明文节点链接，防止云平台日志审计。

---

## 🛠️ 一键安装命令

在服务器终端中执行以下命令即可启动：

```bash
bash <(curl -sL [https://raw.githubusercontent.com/hc990275/kata-nodejs/main/install.sh](https://raw.githubusercontent.com/hc990275/kata-nodejs/main/install.sh))


### 更新说明：适用128M内存以上环境，不建议freecloudpanel使用（64M内存）

* 精简化：去除哪吒、argo隧道；保留3种协议：tuic、hy2、vless+xtls+reality

* uuid自动生成
  
* 自动重启：每天凌晨00:03自动执行一次Sing-box重启，清除缓存
  
* TCP/UDP端口可共用
  
### 使用说明：

1：start.sh+index.js+package.json上传至服务器

2：输入tuic/hy2/vless端口，保存

3：开机
