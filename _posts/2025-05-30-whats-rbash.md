---
title: "`What's Rbash`"
date: 2025-05-30 00:00:00 +0800
categories: [Security, Penetration]
tags: [security, penetration]
---

`rbash（The restricted mode of bash）`，限制型`bash`。它与一般shell的区别在于会限制一些行为，让一些命令无法执行。

## `Escape`
### `1./`
`/bin/bash`

### `2.bash内置命令`
**内置命令（builtin command）** 是 Bash 本身提供的命令，直接由 Bash 解释器执行，不需要调用磁盘上的外部程序。
#### `echo`
`echo os.system("/bin/bash")`

#### `cp`

### `3.`