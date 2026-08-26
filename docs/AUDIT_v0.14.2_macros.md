# ACLM audit v0.14.2 — macro system

## Bugs found and fixed

### 1. Nested macro calls did not work — FIXED
`expand_macros` was a single linear pass: a macro body invoking another
macro was left un-expanded (`unknown statement` at codegen). Rewrote as
a fixed-point loop — re-scan and re-expand until no macro invocation
remains, with a 64-pass depth guard so a macro that invokes itself
(directly or through a chain of other macros) fails with a clear error
instead of hanging or infinitely growing the source.
Regression: `test_330_macro_nested_call.aclm`.

### 2. Calling the same macro twice crashed (CRITICAL) — FIXED
A macro body containing a `~@label` expanded literally at every call
site, but `expand_local_labels` mapped each label name to one fixed
final label for the whole file. Two calls to the same macro therefore
produced two identical labels → `duplicate label` build failure. Every
`~@name` inside a macro body is now given a call-site-unique suffix
(`~@name__mN`) at macro-expansion time, before `expand_local_labels`
ever runs, so no two expansions can collide.
Regression: `test_331_macro_repeat_local_label.aclm`,
`test_332_macro_nested_repeat.aclm` (nested + repeated, combined).

### 3. Missing-argument error was a bare message — FIXED
`raise SystemExit(f"macro {name}: need {len(argnames)} args")` had no
file/line. Now reports `file:line: macro 'name': need N arg(s)
(a, b, ...), got M`, matching the rest of the compiler's error shape.

## Verified green
- Full suite 117/117 (114 prior + 3 new macro regressions)
- Manual stress: same macro called 5x in one file; nested macro called
  2x in one file; self-invoking macro correctly rejected (not hung)

## Scope
No language surface was added or removed — this round is fixes only to
the existing `macro:`/`end:macro` feature described in `docs/CONTRACT.md`.
