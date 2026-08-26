# ACLM std/

Tiny include snippets (macros only). No hidden runtime.

```aclm
include: "print.aclm"
include: "mem.aclm"
include: "exit.aclm"

data:const hi = "hello\n"
println hi
exit0
```

Search path: next to your source, then package `std/`.
