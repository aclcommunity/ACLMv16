# Priority 1 — v0.13.0

## Delivered
1. **`--strict` mode** (`check` and `build`)
   - Errors: `shld`/`shrd` with `reg3` (rcx alias)
   - Warnings: `cmpxchg`+`reg1`, `mulu`/`divu`+`reg1`/`reg4`, dual virt+phys names
2. **CLI** accepts `check --strict file` and `build file --strict`
3. **Includes** continue via `include: "path"` (multi-file, circular detection)
4. **`-g` map** symbol text dump retained

## Usage
```bash
python3 -m aclm.compiler check --strict file.aclm
python3 -m aclm.compiler build file.aclm -o out --strict
```

## Tests
- test_300_strict_ok
- test_301_include_multi
- hardcore: strict blocks /tmp bad shld (exit 2)
