# Version-Aware Exploitation & Compatibility Matrix
## Era-Aware Reconnaissance for CTF Competitions & Security Labs

Applying modern techniques to legacy environments—or legacy techniques to modern mitigated environments—results in guaranteed failure. Always fingerprint target versions before choosing an attack vector.

---

## 1. Binary Exploitation: GNU C Library (glibc) Matrix

Fingerprint the glibc version:
```bash
strings libc.so.6 | grep -i "GNU C Library" | head -1
```

### Era Breakdown & Usable Heap Primitives:

| Glibc Version | Era | Security Features & Changes | Usable Attack Primitives |
|:---|:---|:---|:---|
| **< 2.26** | 2012–2017 | No tcache. Fastbins, unsorted bins, largebins. | Fastbin dup, unsafe unlink, classic House of Orange, House of Force, `__free_hook` / `__malloc_hook`. |
| **2.26 – 2.30** | 2018–2020 | **Tcache introduced** (max 7 chunks per bin). Low integrity checks. | Direct tcache poisoning (single write corrupts fd), tcache double-free (2.26–2.28), tcache stashing unlink. |
| **2.31 – 2.33** | 2020–2021 | Double-free mitigation in tcache (key field). **Safe-linking introduced in 2.32** (`(addr >> 12) ^ ptr`). | Must leak heap base address to de-mangle pointers. `__free_hook` still exists and is writable. |
| **>= 2.34** | 2021–2026+ | **`__free_hook` AND `__malloc_hook` COMPLETELY REMOVED!** Writing to hooks causes crash. | 1. **House of Apple 2** (`_IO_wfile_overflow`).<br>2. TLS destructor overwrite (`__call_tls_dtors` / `__run_exit_handlers`).<br>3. Stack leak via `environ` followed by ROP. |

---

## 2. Web Backend Version Matrix

### PHP Version Nuances
- **PHP 5.x / 7.x**:
  - **Loose string-to-number comparisons**: `"0e12345" == "0e67890"` evaluates to `true` (magic hash flaw).
  - Numeric type juggling: `0 == "admin"` evaluates to `true`.
- **PHP 8.x**:
  - **Breaking change**: String-to-number comparisons are now strict. `"0e123" == "0e456"` is `false`. `0 == "admin"` is `false`.
  - **Rule**: Do NOT attempt numeric type juggling or magic hash attacks against PHP 8 targets!
  - Focus on filter chains (`php://filter`), unserialize gadgets, or fastcgi/fpm injection.

### Python Version & Bytecode Decompilation
- **Python 2.7**:
  - `input()` performs direct `eval()` on user input.
  - `uncompyle6` decompiles `.pyc` files cleanly.
- **Python 3.8 – 3.10**:
  - Standard PyJail breakout via `__subclasses__()`, `builtins`, `sys.modules`.
  - Bytecode formats are standard; decompilation via `uncompyle6` or `decompyle++` (`pycdc`).
- **Python 3.11 – 3.12+**:
  - **PEP 709**: Inlined comprehensions, modified frame object structures, optimized bytecode opcodes.
  - `uncompyle6` fails on Python >= 3.11 bytecode!
  - **Rule**: Always use `pycdc` (C++ decompiler) or disassembler `python3 -m dis <file.pyc>` for Python >= 3.11.

---

## 3. Linux Kernel Mitigation Matrix

| Feature | Introduced | Bypass Technique |
|:---|:---|:---|
| **SMEP** (Supervisor Mode Execution Prevention) | Linux 3.0 | ROP inside kernel space (cannot jump directly to userland shellcode). |
| **SMAP** (Supervisor Mode Access Prevention) | Linux 3.7 | Pivot stack to kernel space; cannot read/write userland stack directly. |
| **KASLR** | Linux 3.14 | Memory leak of kernel text address (`_text`, `commit_creds`). |
| **FG-KASLR** | Linux 5.x | Fine-grained randomization; ROP must use gadgets within leaked function sections. |
| **SLUB Freelist Hardening** | Linux 4.14+ | Freelist pointers XORed with random cookie. Requires heap base leak. |
