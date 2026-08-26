"""ACLM driver — source → ELF64 binary."""

from __future__ import annotations
import os
import sys
from .lexer import Lexer
from .parser import Parser
from .strict import analyze_source, format_warnings, has_errors
from .codegen import CodeGenerator, CodegenError

VERSION = "0.16.0"


def resolve_includes(src: str, filename: str, seen: set | None = None) -> str:
    import re
    seen = seen or set()
    path = os.path.abspath(filename) if filename != "<src>" else filename
    if path in seen:
        raise SystemExit(f"circular include: {path}")
    seen.add(path)
    base_dir = os.path.dirname(path) if path != "<src>" else os.getcwd()
    pkg_std = os.path.join(os.path.dirname(__file__), "..", "std")
    lines = []
    for line in src.splitlines(keepends=True):
        m = re.match(r'^\s*include:\s*"([^"]+)"\s*(#.*)?$', line)
        if m:
            inc = m.group(1)
            candidates = []
            if os.path.isabs(inc):
                candidates.append(inc)
            else:
                candidates.append(os.path.join(base_dir, inc))
                candidates.append(os.path.join(pkg_std, inc))
                candidates.append(os.path.join(pkg_std, os.path.basename(inc)))
            found = next((c for c in candidates if os.path.isfile(c)), None)
            if not found:
                raise SystemExit(f"include not found: {inc}")
            with open(found, "r", encoding="utf-8") as f:
                inc_src = f.read()
            lines.append(f"# ---- include {found} ----\n")
            lines.append(resolve_includes(inc_src, found, seen))
            if not lines[-1].endswith("\n"):
                lines.append("\n")
            lines.append(f"# ---- end include {found} ----\n")
        else:
            lines.append(line)
    return "".join(lines)


def expand_macros(src: str, filename: str = "<src>") -> str:
    """Expand macro: ... end:macro definitions and their call sites.

    Fixes over the original single-pass version:
      1. Nested macro calls (a macro invoking another macro in its body)
         now work: expansion runs as a fixed-point loop -- keep re-scanning
         until no macro invocation remains, with a depth guard against
         infinite recursion (e.g. a macro that calls itself).
      2. Calling the same macro more than once no longer crashes with
         "duplicate label". Any ~@name local-label inside a macro body is
         given a call-site-unique suffix (__mN) at expansion time, before
         the file-wide expand_local_labels pass ever sees it -- so two
         expansions of the same macro never produce the same label text.
      3. The missing-args error now reports file:line:col like every other
         compiler error, instead of a bare SystemExit message.
    """
    import re

    def parse_defs(lines):
        """Scan out every macro: ... end:macro block, return
        (macros dict, remaining lines with definitions removed)."""
        macros = {}
        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r'^\s*macro:\s*([A-Za-z_][\w]*)\s*(.*)$', line)
            if m:
                name = m.group(1)
                args = m.group(2).strip().split()
                body = []
                def_line = i + 1
                i += 1
                closed = False
                while i < len(lines):
                    if re.match(r'^\s*end:macro\s*$', lines[i]):
                        i += 1
                        closed = True
                        break
                    body.append(lines[i])
                    i += 1
                if not closed:
                    raise SystemExit(f"{filename}:{def_line}: macro '{name}': missing end:macro")
                macros[name] = (args, body)
                continue
            out.append(line)
            i += 1
        return macros, out

    lines = src.splitlines(keepends=True)
    macros, lines = parse_defs(lines)

    call_counter = 0
    MAX_PASSES = 64  # guards against a macro that (directly or via a
                      # chain of other macros) invokes itself forever

    def expand_one_pass(lines):
        """Expand every top-level macro call found in `lines` exactly
        once each; macro calls newly introduced by this pass (nested
        macros) are left for the next pass. Returns (new_lines, expanded_any)."""
        nonlocal call_counter
        out = []
        expanded_any = False
        for line_no, line in enumerate(lines, start=1):
            inv = re.match(r'^\s*([A-Za-z_][\w]*)\s+(.+?)\s*$', line)
            name = inv.group(1) if inv else None
            inv0 = re.match(r'^\s*([A-Za-z_][\w]*)\s*$', line) if not inv else None
            name0 = inv0.group(1) if inv0 else None

            if inv and name in macros and ':' not in name:
                call_counter += 1
                vals = [a.strip() for a in re.split(r'[,\s]+', inv.group(2)) if a.strip()]
                argnames, body = macros[name]
                if len(vals) < len(argnames):
                    raise SystemExit(
                        f"{filename}:{line_no}: macro '{name}': need {len(argnames)} "
                        f"arg(s) ({', '.join(argnames)}), got {len(vals)}"
                    )
                mapping = dict(zip(argnames, vals))
                for bl in body:
                    expanded = bl
                    for k, v in mapping.items():
                        expanded = expanded.replace('$' + k, v)
                    # Give every local label inside this macro body a
                    # call-site-unique suffix RIGHT NOW, before
                    # expand_local_labels ever runs -- two calls to the
                    # same macro must not collide on the same final label.
                    expanded = re.sub(
                        r'~@([A-Za-z_][\w]*)',
                        lambda mm: f"~@{mm.group(1)}__m{call_counter}",
                        expanded,
                    )
                    out.append(expanded)
                expanded_any = True
                continue

            if name0 and name0 in macros:
                call_counter += 1
                for bl in macros[name0][1]:
                    expanded = re.sub(
                        r'~@([A-Za-z_][\w]*)',
                        lambda mm: f"~@{mm.group(1)}__m{call_counter}",
                        bl,
                    )
                    out.append(expanded)
                expanded_any = True
                continue

            out.append(line)
        return out, expanded_any

    for _ in range(MAX_PASSES):
        lines, expanded_any = expand_one_pass(lines)
        if not expanded_any:
            break
    else:
        raise SystemExit(
            f"{filename}: macro expansion did not terminate after {MAX_PASSES} passes "
            "(check for a macro that invokes itself, directly or indirectly)"
        )

    return "".join(lines)


def expand_local_labels(src: str) -> str:
    import re
    counter = 0
    mapping = {}
    def repl(m):
        nonlocal counter
        name = m.group(1)
        if name not in mapping:
            counter += 1
            mapping[name] = f"__loc{counter}_{name}"
        return "~" + mapping[name]
    return re.sub(r'~@([A-Za-z_][\w]*)', repl, src)


def compile_source(src: str, filename: str = "<src>", listing: bool = False,
                   debug: bool = False, wx: bool = False, teach: bool = False) -> bytes:
    src = resolve_includes(src, filename)
    src = expand_macros(src, filename)
    src = expand_local_labels(src)
    tokens = Lexer(src, filename=filename).tokenize()
    program = Parser(tokens, filename=filename).parse()
    gen = CodeGenerator(filename=filename)
    gen.emit_listing = listing or teach
    gen.teach_mode = teach
    gen.debug_dwarf = debug
    gen.use_wx = wx
    blob = gen.generate(program)
    if (listing or teach) and gen._listing_lines:
        list_path = (filename if filename != "<src>" else "out") + ".lst"
        with open(list_path, "w", encoding="utf-8") as f:
            f.write("\n".join(gen._listing_lines) + "\n")
        print(f"\033[1;32m[ACLM]\033[0m listing {list_path}")
    return blob


def compile_file(path: str, out_path: str | None = None, listing: bool = False,
                 debug: bool = False, wx: bool = False, teach: bool = False,
                 strict: bool = False, warn: bool = False) -> str:
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    lines = [ln for ln in src.splitlines()
             if not ln.strip().lower().startswith(("@mode:", "mode:"))]
    src = "\n".join(lines)
    if strict or warn:
        expanded = resolve_includes(src, path) if "include:" in src else src
        ws = analyze_source(expanded)
        text = format_warnings(ws)
        if text:
            print(text)
        if strict and has_errors(ws):
            raise SystemExit(2)
    try:
        blob = compile_source(src, filename=path, listing=listing, debug=debug, wx=wx, teach=teach)
    except (SyntaxError, CodegenError, ValueError) as e:
        print(f"[1;31mError[0m: {e}", file=sys.stderr)
        sys.exit(1)
    out = out_path or f"./{os.path.splitext(os.path.basename(path))[0]}"
    with open(out, "wb") as f:
        f.write(blob)
    os.chmod(out, 0o755)
    print(f"[1;32m[ACLM][0m built {out} ({len(blob)} bytes)")
    if debug:
        map_path = out + ".map"
        try:
            text = blob.decode("latin-1", errors="ignore")
            if ".symtab" in text:
                with open(map_path, "w") as mf:
                    mf.write(text[text.find(".symtab"): text.find(".symtab") + 4000])
                print(f"[1;32m[ACLM][0m map {map_path}")
        except Exception:
            pass
    return out


def check_file(path: str, strict: bool = False, warn: bool = False) -> int:
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    try:
        compile_source(src, filename=path)
    except (SyntaxError, CodegenError, ValueError) as e:
        print(f"[1;31mcheck fail[0m: {e}", file=sys.stderr)
        return 1
    if strict or warn:
        expanded = resolve_includes(src, path)
        ws = analyze_source(expanded)
        text = format_warnings(ws)
        if text:
            print(text)
        if strict and has_errors(ws):
            return 2
    print(f"[1;32m[ACLM][0m check ok {path}")
    return 0


def run_file(path: str) -> int:
    import subprocess
    import tempfile
    fd, out = tempfile.mkstemp(prefix="aclm_run_")
    os.close(fd)
    try:
        compile_file(path, out)
        return subprocess.run([out]).returncode
    finally:
        try:
            os.remove(out)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(f"""ACLM {VERSION} — metal language (x86-64 ELF, no nasm/ld)

Commands:
  build <file.aclm> [-o out] [-l|--listing] [--teach] [-g] [--wx] [--strict] [--warn]
  check <file.aclm> [--strict] [--warn]
  run   <file.aclm>
  version

  --strict  ERRORs (shld+reg3, …) fail build (exit 2)
  --warn    print WARN/NOTE only
  --teach   write file.aclm.lst (regs/flags/frames/bytes)

Docs: README.md  docs/CONTRACT.md
Std:  include \"print.aclm\" | \"mem.aclm\" | \"exit.aclm\"
""")
        return 0
    if argv[0] in ("--version", "-V", "version"):
        print(f"ACLM {VERSION}")
        return 0
    if argv[0] == "check":
        files = [a for a in argv[1:] if not a.startswith("-")]
        if not files:
            return 1
        return check_file(files[0], strict=("--strict" in argv), warn=("--warn" in argv))
    if argv[0] == "run":
        return run_file(argv[1]) if len(argv) > 1 else 1
    if argv[0] != "build" or len(argv) < 2:
        print("Usage: build <file.aclm> [-o out] [-l] [--teach] [-g] [--wx]")
        return 1
    files = [a for a in argv[1:] if not a.startswith("-") and a != (argv[argv.index("-o")+1] if "-o" in argv else None)]
    # path is first non-flag non-out-value arg
    path = None
    skip = set()
    if "-o" in argv:
        skip.add(argv[argv.index("-o") + 1])
    for a in argv[1:]:
        if a.startswith("-"):
            continue
        if a in skip:
            continue
        path = a
        break
    if not path:
        print("Usage: build <file.aclm> ...")
        return 1
    out = argv[argv.index("-o") + 1] if "-o" in argv else None
    compile_file(
        path, out,
        listing=("--listing" in argv or "-l" in argv),
        debug=("--debug" in argv or "-g" in argv),
        wx=("--wx" in argv),
        teach=("--teach" in argv),
        strict=("--strict" in argv),
        warn=("--warn" in argv),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
