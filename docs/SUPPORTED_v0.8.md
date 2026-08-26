# ACLM supported surface (v0.8)

See README for overview. This file lists stages.

## Core metal
cpu:*, ram:*, data:*, cmp, jump_if, goto, call, ret, stack:*, sys:call

## Stage-2
blast:fill/copy, wire:*, trap:neg, aliases mem/str/err

## Stage-3
cell:map/free, gate:cas/spin, pulse:sleep/now

## Stage-4 hardware
flag:setcc, chip:ticks/id/cli/sti/halt, gate:fence, port:*, vec: SSE, cpu:lea, sys numeric

## Stage-5 ASM-plus
raw:, full addressing, cpu:cmov, include:, --listing

## Priority-1 product
macros, local labels ~@x, thread:*, AVX vec:v*, err:status

## Priority A
cpu:xchg/xadd/bsf/bsr/bt, blast:rep_*, net:*, target:baremetal, -g DWARF, --wx

## Priority 1 (v0.8)
- thread join via done/joined counters + futex (multi join)
- thread:exit signals completion
- baremetal VGA body (cli + write 0xb8000 + hlt)
- -g symbol name dump (.symtab marker)
- std/ snippets + include search path
- CLI: build / run / check / --version
