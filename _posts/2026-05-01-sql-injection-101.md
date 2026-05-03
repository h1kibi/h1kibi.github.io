---
title: "SQL Injection 101"
date: 2026-05-01 10:00:00 +0800
categories: [Security]
tags: [sql-injection, web-security]
---

## The Simplest Attack

Suppose the backend query looks like this:

```sql
SELECT * FROM users WHERE name = '$input' AND pass = '$input';
```

Input `admin' --`, password anything, SQL becomes:

```sql
SELECT * FROM users WHERE name = 'admin' --' AND pass = 'xxx';
```

`--` comments out everything after. Login successful.

## Defense

**Parameterized queries**. Never concatenate SQL.

```python
# Wrong
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# Correct
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

## Principle

> Never trust user input.

---

```
$ sudo rm -rf /  # don't
```
