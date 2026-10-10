#!/usr/bin/env python3
"""AsyncSan Binary Qualifier — detect non-trivial signal handlers in binaries.

Uses angr to find signal/sigaction calls, extract handler functions,
and determine if handlers are trivial (just set flags) or non-trivial
(call async-signal-unsafe functions).

Usage:
    python3 asyncsan-qualify.py <binary>

Workflow:
    1. Build project with asyncsan flags
    2. Run this script to check if binary has dangerous handlers
    3. If yes → run fuzzer with asyncsan
"""

import sys
import time
import argparse

import angr
import archinfo
from capstone import CsInsn


# POSIX async-signal-unsafe functions (subset — most common)
ASYNC_SIGNAL_UNSAFE = frozenset({
    "malloc", "free", "calloc", "realloc",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf",
    "puts", "fputs", "fgets", "fread", "fwrite", "fopen", "fclose", "fflush",
    "getchar", "getc", "ungetc",
    "strerror", "strsignal",
    "syslog", "vsyslog", "openlog", "closelog",
    "exit", "atexit", "_exit",
    "setlocale",
    "asctime", "localtime", "gmtime", "ctime", "strftime",
    "longjmp", "siglongjmp",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "dlopen", "dlsym", "dlclose",
    "getpwnam", "getpwuid", "getgrnam", "getgrgid",
    "gethostbyname", "gethostbyaddr",
})

# Signal registration functions
_REG_BASE = {"signal", "sigaction", "sigset", "bsd_signal", "__sysv_signal"}


def _strip_underscore(name):
    """Strip leading underscore from Mach-O symbol names."""
    if name and name.startswith("_") and not name.startswith("__"):
        return name[1:]
    return name


def _build_stub_map(proj):
    """Build stub address → symbol name map for Mach-O binaries.

    Handles both traditional __stubs (PLT) and arm64e __auth_stubs.
    Each stub loads a GOT entry and branches to it. We match stubs to
    import symbols by GOT slot address.
    """
    obj = proj.loader.main_object
    plt = getattr(obj, 'plt', None) or {}
    if plt:
        return {addr: _strip_underscore(name) for name, addr in plt.items()}

    # No PLT — use otool to get indirect symbol table (Mach-O specific).
    # Handles __auth_stubs (arm64e) and __stubs.
    import subprocess
    stub_map = {}
    try:
        r = subprocess.run(
            ['otool', '-Iv', obj.binary],
            capture_output=True, text=True, timeout=10
        )
        in_stubs = False
        for line in r.stdout.split('\n'):
            if 'stub' in line and 'Indirect' in line:
                # Header: "Indirect symbols for (__TEXT,__auth_stubs) N entries"
                in_stubs = True
                continue
            if 'Indirect' in line and 'stub' not in line:
                # Different section header — stop
                in_stubs = False
                continue
            if not in_stubs:
                continue
            if line.strip().startswith('address'):
                continue
            parts = line.strip().split()
            if len(parts) >= 3:
                try:
                    addr = int(parts[0], 16)
                    name = _strip_underscore(parts[2])
                    stub_map[addr] = name
                except (ValueError, IndexError):
                    pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return stub_map


def _get_reg_plt_addrs(proj):
    """Get PLT/stub addresses for signal registration functions."""
    stub_map = _build_stub_map(proj)
    return {addr: name for addr, name in stub_map.items()
            if name in _REG_BASE}


def _get_all_plt_addrs(proj):
    """Get all PLT/stub addresses → name mapping."""
    return _build_stub_map(proj)


def _get_text_range(proj):
    """Get the text section address range."""
    obj = proj.loader.main_object
    # Try sections first
    for sec in obj.sections:
        if sec.name in ('.text', '__text'):
            return sec.vaddr, sec.vaddr + sec.memsize
    # Fallback: use segments
    for seg in obj.segments:
        if seg.is_executable:
            return seg.vaddr, seg.vaddr + seg.memsize
    # Last resort
    return obj.min_addr, obj.max_addr


def _get_function_symbols(proj):
    """Get function symbol table: addr → name.

    Includes non-function symbols in the text range since Mach-O local
    symbols often lack the function type flag. For stripped x86-64 ELF
    binaries, uses endbr64 instructions as function-start heuristic.
    """
    text_start, text_end = _get_text_range(proj)
    syms = {}
    for sym in proj.loader.symbols:
        if sym.rebased_addr <= 0:
            continue
        if sym.is_import or sym.is_extern:
            continue
        # Include if marked as function OR if it falls in the text section
        if sym.is_function or text_start <= sym.rebased_addr < text_end:
            syms[sym.rebased_addr] = _strip_underscore(sym.name)

    # For stripped x86-64 binaries, detect function starts via endbr64
    text_func_count = sum(1 for a in syms if text_start <= a < text_end)
    if text_func_count < 20 and isinstance(proj.arch, archinfo.ArchAMD64):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        data = proj.loader.memory.load(text_start, text_end - text_start)
        for insn in cs.disasm(data, text_start):
            if insn.mnemonic == 'endbr64' and insn.address not in syms:
                syms[insn.address] = f"sub_{insn.address:x}"

    return syms


def _find_enclosing_function(addr, func_starts, func_syms):
    """Find which function contains addr using sorted function start list."""
    # Binary search for largest start <= addr
    lo, hi = 0, len(func_starts) - 1
    result = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if func_starts[mid] <= addr:
            result = func_starts[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if result is not None:
        return result, func_syms.get(result, f"sub_{result:x}")
    return None, None


def _disasm_range(proj, start, end):
    """Disassemble a range and yield (addr, insn) pairs using capstone."""
    size = end - start
    try:
        data = proj.loader.memory.load(start, size)
    except Exception:
        return
    block = proj.factory.block(start, size=min(size, 0x10000), opt_level=0)
    for insn in block.capstone.insns:
        yield insn


def _disasm_function(proj, func_addr, func_starts_sorted):
    """Disassemble a single function from func_addr to next function start."""
    idx = None
    lo, hi = 0, len(func_starts_sorted) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if func_starts_sorted[mid] == func_addr:
            idx = mid
            break
        elif func_starts_sorted[mid] < func_addr:
            lo = mid + 1
        else:
            hi = mid - 1

    if idx is None:
        # Function not in symbol table — disassemble a reasonable chunk
        end = func_addr + 0x1000
    elif idx + 1 < len(func_starts_sorted):
        end = func_starts_sorted[idx + 1]
    else:
        end = func_addr + 0x4000  # last function, cap at 16KB

    size = min(end - func_addr, 0x10000)
    if size <= 0:
        return []

    try:
        block = proj.factory.block(func_addr, size=size, opt_level=0)
        insns = list(block.capstone.insns)
        # Trim at first ret instruction for safety
        trimmed = []
        for insn in insns:
            trimmed.append(insn)
            if insn.mnemonic == 'ret':
                break
        return trimmed
    except Exception:
        return []


def _resolve_adrp_add(insns, idx):
    """Resolve adrp+add pair at insns[idx]. Returns address or None."""
    insn = insns[idx]
    if insn.mnemonic == 'adrp' and len(insn.operands) >= 2:
        page = insn.operands[1].imm
        if idx + 1 < len(insns):
            nxt = insns[idx + 1]
            if (nxt.mnemonic == 'add' and len(nxt.operands) >= 3
                    and nxt.reg_name(nxt.operands[0].reg)
                    == insn.reg_name(insn.operands[0].reg)):
                if hasattr(nxt.operands[2], 'imm'):
                    return page + nxt.operands[2].imm
        return page
    elif insn.mnemonic == 'adr' and len(insn.operands) >= 2:
        return insn.operands[1].imm
    return None


def _linear_disasm(proj, start, size):
    """Linear disassembly using capstone directly (not angr blocks)."""
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64
    arch = proj.arch
    if isinstance(arch, archinfo.ArchAArch64):
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif isinstance(arch, archinfo.ArchAMD64):
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        return []
    cs.detail = True
    data = proj.loader.memory.load(start, size)
    return list(cs.disasm(data, start))


def find_reg_calls_fast(proj):
    """Find all calls to signal/sigaction using linear scan. No CFGFast.

    Also auto-detects wrapper functions: any internal function that calls
    sigaction/signal is treated as a wrapper (e.g., ssh_setsig, pqsignal).
    """
    reg_addrs = _get_reg_plt_addrs(proj)
    if not reg_addrs:
        return [], []

    text_start, text_end = _get_text_range(proj)
    func_syms = _get_function_symbols(proj)
    func_starts = sorted(func_syms.keys())

    # Linear disassemble entire text section
    insns = _linear_disasm(proj, text_start, text_end - text_start)

    calls = []
    # Track which functions call sigaction/signal → these are wrappers
    wrapper_callers = {}  # caller_addr → caller_name

    for i, insn in enumerate(insns):
        if insn.mnemonic not in ('bl', 'call', 'callq'):
            continue
        if not insn.operands or not hasattr(insn.operands[0], 'imm'):
            continue
        target = insn.operands[0].imm
        if target not in reg_addrs:
            continue

        reg_fn = reg_addrs[target]
        caller_addr, caller_name = _find_enclosing_function(
            insn.address, func_starts, func_syms
        )
        calls.append({
            "reg_fn": reg_fn,
            "call_addr": insn.address,
            "call_idx": i,
            "caller_addr": caller_addr,
            "caller_name": caller_name or f"sub_{insn.address:x}",
            "preceding_insns": insns[max(0, i - 30):i],
            "all_insns": insns,
        })

        # Record as potential wrapper — even without symbol, use call addr
        # to backward-scan for the function prologue (endbr64 / push rbp)
        if caller_addr is not None:
            wrapper_callers[caller_addr] = caller_name or f"sub_{caller_addr:x}"
        else:
            # Stripped binary fallback: scan backward for function prologue
            for j in range(i - 1, max(0, i - 500), -1):
                if insns[j].mnemonic in ('endbr64', 'endbr32'):
                    wrapper_callers[insns[j].address] = f"sub_{insns[j].address:x}"
                    break
                if insns[j].mnemonic == 'ret':
                    # Likely start of function is next instruction
                    if j + 1 < len(insns):
                        wrapper_callers[insns[j+1].address] = f"sub_{insns[j+1].address:x}"
                    break

    # Auto-detect wrappers: find all callers of each wrapper function
    # and extract handler args from them
    wrappers = []
    for wrapper_addr, wrapper_name in wrapper_callers.items():
        wrappers.append({
            "addr": wrapper_addr,
            "name": wrapper_name,
        })

    return calls, wrappers


def _extract_arg_from_preceding(preceding, target_reg, func_syms):
    """Scan backward through preceding instructions to find a function address
    loaded into target_reg. Follows register chains (mov rsi, rbx → trace rbx)."""
    regs_to_check = {target_reg}
    for j in range(len(preceding) - 1, -1, -1):
        p = preceding[j]
        if len(p.operands) < 2:
            continue
        dst = p.reg_name(p.operands[0].reg) if p.operands[0].type == 1 else None
        if dst not in regs_to_check:
            continue
        if p.mnemonic == 'adrp':
            return _resolve_adrp_add(preceding, j)
        if p.mnemonic == 'adr':
            return p.operands[1].imm
        if p.mnemonic in ('lea', 'mov'):
            op1 = p.operands[1]
            if op1.type == 3:  # MEM (x86-64 RIP-relative lea)
                base = p.reg_name(op1.mem.base) if op1.mem.base else None
                if base == 'rip':
                    return p.address + p.size + op1.mem.disp
            elif op1.type == 1:  # REG — follow the chain
                regs_to_check.add(p.reg_name(op1.reg))
            elif hasattr(op1, 'imm'):
                return op1.imm
        if p.mnemonic == 'xor' and p.operands[1].type == 1:
            # xor reg, reg = 0 (SIG_DFL), stop searching this chain
            regs_to_check.discard(dst)
    return None


def _find_wrapper_callers(proj, wrapper_addr, wrapper_name,
                          func_syms, func_starts, all_plt, reg_calls):
    """Find callers of a wrapper function and extract handler args from them.

    When signal/sigaction is called from a wrapper like pqsignal(signum, handler),
    the actual handler is passed as an argument. We find all call sites of the
    wrapper and extract the handler argument (2nd arg = x1/rsi).
    """
    text_start, text_end = _get_text_range(proj)
    arch = proj.arch
    handlers = []

    if isinstance(arch, archinfo.ArchAArch64):
        target_reg = "x1"
    elif isinstance(arch, archinfo.ArchAMD64):
        target_reg = "rsi"
    else:
        return handlers

    insns = _linear_disasm(proj, text_start, text_end - text_start)

    for i, insn in enumerate(insns):
        if insn.mnemonic not in ('bl', 'call', 'callq'):
            continue
        if not insn.operands or not hasattr(insn.operands[0], 'imm'):
            continue
        if insn.operands[0].imm != wrapper_addr:
            continue

        # Found a call to the wrapper. Extract 2nd arg (handler).
        preceding = insns[max(0, i - 30):i]
        handler_addr = _extract_arg_from_preceding(preceding, target_reg, func_syms)
        if handler_addr and handler_addr in func_syms:
            hname = func_syms[handler_addr]
            _, caller_name = _find_enclosing_function(
                insn.address, func_starts, func_syms
            )
            analysis = analyze_handler(proj, handler_addr, func_starts, all_plt)
            handlers.append({
                "reg_fn": f"{wrapper_name}→sigaction",
                "handler_name": hname,
                "handler_addr": handler_addr,
                "caller": caller_name or f"sub_{insn.address:x}",
                "is_trivial": analysis["is_trivial"],
                "unsafe_calls": analysis["unsafe_calls"],
                "all_calls": analysis["all_calls"],
            })

    return handlers


def extract_handler(proj, call_info, func_syms, func_starts):
    """Extract handler function address from a registration call site."""
    reg_fn = call_info["reg_fn"]
    arch = proj.arch
    preceding = call_info["preceding_insns"]

    if reg_fn == "sigaction":
        # sigaction: handler stored in struct. Scan preceding instructions
        # for adrp+add pairs or lea [rip+off] that resolve to known functions.
        candidates = []
        for i, insn in enumerate(preceding):
            addr = _resolve_adrp_add(preceding, i)
            if addr is None and insn.mnemonic == 'lea' and len(insn.operands) >= 2:
                op1 = insn.operands[1]
                if op1.type == 3:  # MEM operand
                    base = insn.reg_name(op1.mem.base) if op1.mem.base else None
                    if base == 'rip':
                        addr = insn.address + insn.size + op1.mem.disp
                elif hasattr(op1, 'imm'):
                    addr = op1.imm
            if addr is not None and addr in func_syms:
                name = func_syms[addr]
                if name not in _REG_BASE and name != call_info["caller_name"]:
                    candidates.append(addr)
        return candidates[0] if candidates else None

    # signal(): handler is 2nd arg register
    if isinstance(arch, archinfo.ArchAArch64):
        target_reg = "x1"
    elif isinstance(arch, archinfo.ArchAMD64):
        target_reg = "rsi"
    else:
        return None

    for i in range(len(preceding) - 1, -1, -1):
        insn = preceding[i]
        if insn.mnemonic == 'adrp' and len(insn.operands) >= 2:
            dst = insn.reg_name(insn.operands[0].reg)
            if dst == target_reg:
                addr = _resolve_adrp_add(preceding, i)
                if addr is not None:
                    return addr
        if insn.mnemonic == 'adr' and len(insn.operands) >= 2:
            dst = insn.reg_name(insn.operands[0].reg)
            if dst == target_reg:
                return insn.operands[1].imm
        if insn.mnemonic in ('lea', 'mov') and len(insn.operands) >= 2:
            dst = insn.reg_name(insn.operands[0].reg)
            if dst == target_reg and hasattr(insn.operands[1], 'imm'):
                return insn.operands[1].imm

    return None


def analyze_handler(proj, handler_addr, func_starts, all_plt):
    """Analyze handler function for unsafe calls. Returns analysis dict."""
    insns = _disasm_function(proj, handler_addr, func_starts)
    unsafe_calls = []
    all_calls = []

    for insn in insns:
        if insn.mnemonic not in ('bl', 'call', 'callq', 'blr'):
            continue
        target = None
        if insn.mnemonic in ('bl', 'call', 'callq'):
            if insn.operands and hasattr(insn.operands[0], 'imm'):
                target = insn.operands[0].imm

        if target:
            name = all_plt.get(target)
            if name:
                all_calls.append(name)
                if name in ASYNC_SIGNAL_UNSAFE:
                    unsafe_calls.append(name)
            else:
                all_calls.append(f"func@{target:x}")
        else:
            all_calls.append(f"indirect@{insn.address:x}")

    return {
        "is_trivial": len(unsafe_calls) == 0,
        "unsafe_calls": unsafe_calls,
        "all_calls": all_calls,
    }


def _scan_shared_libs(proj, verbose=False):
    """Scan shared libraries for signal handler registrations.

    When main binary shows no handlers (e.g. macOS sshd), signal setup
    may happen in linked dylibs/SOs. We reload with auto_load_libs=True
    and scan each loaded object.
    """
    import os
    binary_path = proj.loader.main_object.binary
    print(f"[*] Scanning shared libraries for signal registrations...")

    try:
        proj2 = angr.Project(binary_path, auto_load_libs=True)
    except Exception as e:
        print(f"[!] Failed to load with shared libs: {e}")
        return []

    handlers = []
    for obj in proj2.loader.all_objects:
        if obj.binary is None:
            continue
        obj_name = os.path.basename(obj.binary)
        if obj_name.startswith('cle##'):
            continue

        # Get text range for this object
        text_start = text_end = None
        for sec in obj.sections:
            if sec.name in ('.text', '__text'):
                text_start = sec.vaddr
                text_end = sec.vaddr + sec.memsize
                break
        if text_start is None:
            for seg in obj.segments:
                if seg.is_executable:
                    text_start = seg.vaddr
                    text_end = seg.vaddr + seg.memsize
                    break
        if text_start is None:
            continue

        # Build stub map for this object
        plt = getattr(obj, 'plt', None) or {}
        stub_map = {addr: _strip_underscore(name) for name, addr in plt.items()} if plt else {}

        reg_addrs = {addr: name for addr, name in stub_map.items()
                     if name in _REG_BASE}
        if not reg_addrs:
            continue

        print(f"[*]   {obj_name}: found signal API in PLT, scanning...")

        # Get symbols for this object
        obj_syms = {}
        for sym in obj.symbols:
            if sym.rebased_addr <= 0 or sym.is_import or sym.is_extern:
                continue
            if sym.is_function or text_start <= sym.rebased_addr < text_end:
                obj_syms[sym.rebased_addr] = _strip_underscore(sym.name)

        func_starts = sorted(obj_syms.keys())

        # Linear disasm
        try:
            insns = _linear_disasm(proj2, text_start, text_end - text_start)
        except Exception:
            continue

        for i, insn in enumerate(insns):
            if insn.mnemonic not in ('bl', 'call', 'callq'):
                continue
            if not insn.operands or not hasattr(insn.operands[0], 'imm'):
                continue
            target = insn.operands[0].imm
            if target not in reg_addrs:
                continue

            reg_fn = reg_addrs[target]
            preceding = insns[max(0, i - 30):i]

            # Try extract handler from preceding instructions
            handler_addr = None
            # For sigaction: scan for function addresses loaded before call
            for j, p in enumerate(preceding):
                addr = _resolve_adrp_add(preceding, j)
                if addr is None and p.mnemonic in ('lea', 'mov') and len(p.operands) >= 2:
                    if hasattr(p.operands[1], 'imm'):
                        addr = p.operands[1].imm
                if addr is not None and addr in obj_syms:
                    name = obj_syms[addr]
                    if name not in _REG_BASE:
                        handler_addr = addr

            if handler_addr:
                hname = obj_syms.get(handler_addr, f"sub_{handler_addr:x}")
                _, caller_name = _find_enclosing_function(
                    insn.address, func_starts, obj_syms
                )
                analysis = analyze_handler(proj2, handler_addr, func_starts, stub_map)
                handlers.append({
                    "reg_fn": reg_fn,
                    "handler_name": hname,
                    "handler_addr": handler_addr,
                    "caller": f"{obj_name}::{caller_name or f'sub_{insn.address:x}'}",
                    "is_trivial": analysis["is_trivial"],
                    "unsafe_calls": analysis["unsafe_calls"],
                    "all_calls": analysis["all_calls"],
                })

    return handlers


def qualify_binary(binary_path, verbose=False, scan_libs=False):
    """Main entry point: analyze a binary for non-trivial signal handlers."""
    t_start = time.time()

    print(f"[*] Loading binary: {binary_path}")
    proj = angr.Project(binary_path, auto_load_libs=False)
    print(f"[*] Architecture: {proj.arch.name}")

    t_load = time.time()

    # Fast scan — no CFGFast
    print(f"[*] Scanning for signal handler registrations (fast mode)...")
    reg_calls, wrappers = find_reg_calls_fast(proj)

    t_scan = time.time()

    func_syms = _get_function_symbols(proj)
    func_starts = sorted(func_syms.keys())
    all_plt = _get_all_plt_addrs(proj)

    # Extract and analyze handlers
    handlers = []
    unresolved = []
    seen_handlers = set()  # dedup by handler address

    # Phase 1: direct handler extraction from registration call sites
    for call in reg_calls:
        handler_addr = extract_handler(proj, call, func_syms, func_starts)
        if handler_addr and handler_addr not in seen_handlers:
            seen_handlers.add(handler_addr)
            handler_name = func_syms.get(handler_addr, f"sub_{handler_addr:x}")
            analysis = analyze_handler(proj, handler_addr, func_starts, all_plt)
            handlers.append({
                "reg_fn": call["reg_fn"],
                "handler_name": handler_name,
                "handler_addr": handler_addr,
                "caller": call["caller_name"],
                "is_trivial": analysis["is_trivial"],
                "unsafe_calls": analysis["unsafe_calls"],
                "all_calls": analysis["all_calls"],
            })

    # Phase 2: proactively resolve ALL wrapper functions.
    # Any function that calls sigaction/signal is a wrapper (e.g.,
    # ssh_setsig, pqsignal). Find all callers and extract handler args.
    if wrappers:
        print(f"[*] Auto-detected {len(wrappers)} wrapper function(s): "
              f"{', '.join(w['name'] for w in wrappers)}")
    for wrapper in wrappers:
        wrapper_handlers = _find_wrapper_callers(
            proj, wrapper["addr"], wrapper["name"],
            func_syms, func_starts, all_plt, reg_calls
        )
        for wh in wrapper_handlers:
            if wh["handler_addr"] not in seen_handlers:
                seen_handlers.add(wh["handler_addr"])
                handlers.append(wh)

    # If --scan-libs, also scan shared libraries
    if scan_libs:
        lib_handlers = _scan_shared_libs(proj, verbose=verbose)
        handlers.extend(lib_handlers)

    t_end = time.time()

    # Report
    print()
    print("=" * 65)
    print("AsyncSan Binary Qualification Report")
    print("=" * 65)
    print(f"  Time: {t_end - t_start:.1f}s "
          f"(load {t_load - t_start:.1f}s, scan {t_scan - t_load:.1f}s, "
          f"analyze {t_end - t_scan:.1f}s)")

    if not handlers and not unresolved:
        # Try shared libraries before giving up
        lib_handlers = _scan_shared_libs(proj, verbose=verbose)
        if lib_handlers:
            handlers = lib_handlers
            t_end = time.time()
        else:
            print("\n  No signal handler registrations found.")
            print("  Binary does not use signal handlers — no async-safety risk.")
            print(f"\n  VERDICT: SKIP (no handlers)")
            return False

    nontrivial = [h for h in handlers if not h["is_trivial"]]
    trivial = [h for h in handlers if h["is_trivial"]]

    if handlers:
        print(f"\n  Signal handlers found: {len(handlers)}")
        for h in handlers:
            tag = "TRIVIAL" if h["is_trivial"] else "NON-TRIVIAL"
            print(f"    [{tag}] {h['handler_name']} "
                  f"(registered by {h['caller']} via {h['reg_fn']})")
            if not h["is_trivial"] and h["unsafe_calls"]:
                print(f"      Unsafe calls: {', '.join(set(h['unsafe_calls']))}")
            if verbose and h["all_calls"]:
                print(f"      All calls: {', '.join(h['all_calls'])}")

    if unresolved:
        known_callers = {h["caller"] for h in handlers}
        unresolved_new = [u for u in unresolved
                          if u["caller_name"] not in known_callers]
        if unresolved_new:
            print(f"\n  Unresolved {unresolved_new[0]['reg_fn']}() calls: "
                  f"{len(unresolved_new)}")
            for u in unresolved_new:
                print(f"    Called from: {u['caller_name']} "
                      f"at {hex(u['call_addr'])}")

    print()
    if nontrivial:
        print(f"  VERDICT: FUZZ — {len(nontrivial)} non-trivial handler(s) found")
        return True
    elif unresolved:
        print(f"  VERDICT: INVESTIGATE — handler extraction needs manual review")
        return True
    else:
        print(f"  VERDICT: SKIP — all {len(trivial)} handler(s) are trivial")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="AsyncSan Binary Qualifier — detect non-trivial "
                    "signal handlers in binaries"
    )
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all function calls in handlers")
    parser.add_argument("--scan-libs", action="store_true",
                        help="Also scan shared libraries for signal handlers")
    args = parser.parse_args()

    should_fuzz = qualify_binary(args.binary, verbose=args.verbose,
                                 scan_libs=args.scan_libs)
    sys.exit(0 if should_fuzz else 1)


if __name__ == "__main__":
    main()
