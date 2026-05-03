---
title: "My Terminal Workflow"
date: 2026-05-03 20:00:00 +0800
categories: [Infra]
tags: [terminal, workflow, tools]
---

## Everything Starts from Terminal

If it can be done with keyboard, never touch the mouse.

### My Toolchain

```bash
# Editor
$ nvim .

# File manager
$ lsd -la

# Git
$ lazygit

# Terminal
$ Windows Terminal + PowerShell 7
```

### Why Terminal?

1. **Fast** — No digging through menus
2. **Reproducible** — Commands can be scripted
3. **Focus** — No flashy UI distractions

### A Useful Alias

```powershell
# PowerShell $PROFILE
function blog {
    Set-Location "C:\Projects\mysite\blog"
    bundle exec jekyll serve --host 127.0.0.1
}
```

Now just type `blog` in terminal to start local preview.

---

```
$ which productivity
/usr/local/bin/productivity -> terminal
```
