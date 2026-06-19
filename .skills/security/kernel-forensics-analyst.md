---
name: kernel-forensics-analyst
tier: HIGH
auto_escalate: true
domains: [memory-forensics, rootkit, DKOM, syscall-hooks, kernel-exploit, EDR-bypass]
---

## Activation
Load on: volatile memory analysis, kernel exploit triage, rootkit detection, DKOM artifacts,
syscall hook detection, kernel module RE, process injection, credential dumping forensics,
ring-0 code execution, SSDT/IDT hooks, UEFI implant analysis.

## Evidence Chain of Custody
```
Acquisition:  RAM dump via LiME (Linux) / winpmem (Windows) — before any remediation
Hash:         SHA-256 of raw dump — executor-verified, never linguistically generated
Chain:        every analysis step documented with tool + version + timestamp
Preservation: read-only mount or copy-on-write; never modify evidence
```

## Linux Kernel Artifact Taxonomy
```
task_struct walk     → compare pslist vs psscan (DKOM gap = hidden process)
module list          → /proc/modules vs /sys/module vs kobject walk
syscall table        → sys_call_table[] vs expected addresses (kallsyms)
netfilter hooks      → nf_hooks[] entries pointing outside kernel text
vDSO/vsyscall        → unexpected mappings in [vsyscall] range
eBPF programs        → bpftool prog list — unexpected KPROBE/TRACEPOINT
ftrace hooks         → check ftrace_ops list for unauthorized entries
```

## Windows Kernel Artifact Taxonomy
```
EPROCESS/PEB         → ActiveProcessLinks walk; DKOM if gap vs PspCidTable
SSDT hooks           → KeServiceDescriptorTable entries outside ntoskrnl range
IDT hooks            → idt_table[0x80] → compare against expected ISR
Driver objects       → DriverSection list walk vs PsLoadedModuleList
KTHREAD/KAPC         → APC queue inspection for kernel APC injection
MmUnloadedDrivers    → recently unloaded driver artifacts
```

## Volatility3 Command Sequences
```bash
# Linux
vol -f dump.raw linux.pslist | diff - <(vol -f dump.raw linux.psscan)
vol -f dump.raw linux.lsmod
vol -f dump.raw linux.check_syscall
vol -f dump.raw linux.netstat

# Windows
vol -f dump.raw windows.pstree
vol -f dump.raw windows.dlllist --pid <PID>
vol -f dump.raw windows.malfind
vol -f dump.raw windows.ssdt
vol -f dump.raw windows.modules | diff - <(vol -f dump.raw windows.driverscan)
vol -f dump.raw windows.netscan
vol -f dump.raw windows.cmdline
vol -f dump.raw windows.hashdump  # credential artifacts
```

## ROP/JOP Chain Analysis
```
gadget_graph:   ROPgadget --binary target --rop --multibr | sort -u
pivot_chain:    trace RSP manipulation sequence
constraint_check: ASLR defeat method (leak/brute/heap spray)
CFI_bypass:     identify indirect call targets if CFI present
```

## Output: epistemic tagging mandatory
[PROVEN] = artifact in memory dump, address confirmed
[INFERENCE] = behavioral indicator consistent with class of technique
[SPECULATIVE] = possible based on partial evidence, needs additional memory region
