#!/usr/bin/env python3
"""Diagnostic: check what angr sees in sshd PLT and text section."""
import angr

proj = angr.Project('/usr/sbin/sshd', auto_load_libs=False)
obj = proj.loader.main_object
plt = getattr(obj, 'plt', None) or {}

print(f"PLT entries: {len(plt)}")
for n, a in sorted(plt.items()):
    if 'sig' in n.lower():
        print(f"  {n} @ {hex(a)}")

syms = [s for s in proj.loader.symbols
        if not s.is_import and not s.is_extern and s.is_function]
print(f"\nNon-import function symbols: {len(syms)}")
for s in syms[:10]:
    print(f"  {hex(s.rebased_addr)}: {s.name}")

# Check text section
for sec in obj.sections:
    if sec.name == '.text':
        print(f"\n.text: {hex(sec.vaddr)} - {hex(sec.vaddr + sec.memsize)}")
        print(f"  size: {sec.memsize} bytes")
        break

# Quick check: any call to sigaction?
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sig_addrs = {a for n, a in plt.items()
             if n in ('sigaction', 'signal', 'sigset')}
print(f"\nSignal PLT targets: {[hex(a) for a in sig_addrs]}")

if sig_addrs:
    for sec in obj.sections:
        if sec.name == '.text':
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            cs.detail = True
            data = proj.loader.memory.load(sec.vaddr, sec.memsize)
            hits = 0
            for insn in cs.disasm(data, sec.vaddr):
                if insn.mnemonic in ('call', 'callq'):
                    if insn.operands and insn.operands[0].type == 2:
                        if insn.operands[0].imm in sig_addrs:
                            hits += 1
                            print(f"  call sigaction @ {hex(insn.address)}")
            print(f"Total calls to signal API: {hits}")
            break
