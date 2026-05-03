---
title: "Binary Search Boundary Problem"
date: 2026-05-02 14:00:00 +0800
categories: [Algorithm]
tags: [binary-search, leetcode]
---

## Classic Problem

Binary search looks simple, but boundary conditions are a minefield.

```python
def binary_search(nums, target):
    lo, hi = 0, len(nums) - 1
    while lo <= hi:
        mid = lo + (hi - lo) // 2
        if nums[mid] == target:
            return mid
        elif nums[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1
```

## Common Mistakes

| Code | Problem |
|------|---------|
| `mid = (lo + hi) // 2` | Potential overflow |
| `lo < hi` | Misses single-element case |
| `hi = mid` | Infinite loop when `lo + 1 == hi` |

## Memory Aid

> Closed interval uses `<=`, half-open uses `<`.
> `hi = mid - 1` or `hi = mid` depends on your interval definition.

---

```
$ rm -rf bug
```
