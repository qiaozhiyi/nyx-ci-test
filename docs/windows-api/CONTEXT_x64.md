# CONTEXT Structure (x86 64-bit) - Win32 apps

Contains processor-specific register data. The system uses CONTEXT structures to perform various internal operations. This page applies to the **64-bit x86 architecture**.

## Architecture Links

| Architecture | API reference page |
|---|---|
| x86 32-bit | [CONTEXT structure (x86 32-bit)](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) |
| Arm32 | [CONTEXT structure (Arm32)](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context_r) |
| Arm64 | [ARM64_NT_CONTEXT structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-arm64_nt_context) |

## Syntax

```c
typedef struct _CONTEXT {
  DWORD64 P1Home;
  DWORD64 P2Home;
  DWORD64 P3Home;
  DWORD64 P4Home;
  DWORD64 P5Home;
  DWORD64 P6Home;
  DWORD   ContextFlags;
  DWORD   MxCsr;
  WORD    SegCs;
  WORD    SegDs;
  WORD    SegEs;
  WORD    SegFs;
  WORD    SegGs;
  WORD    SegSs;
  DWORD   EFlags;
  DWORD64 Dr0;
  DWORD64 Dr1;
  DWORD64 Dr2;
  DWORD64 Dr3;
  DWORD64 Dr6;
  DWORD64 Dr7;
  DWORD64 Rax;
  DWORD64 Rcx;
  DWORD64 Rdx;
  DWORD64 Rbx;
  DWORD64 Rsp;
  DWORD64 Rbp;
  DWORD64 Rsi;
  DWORD64 Rdi;
  DWORD64 R8;
  DWORD64 R9;
  DWORD64 R10;
  DWORD64 R11;
  DWORD64 R12;
  DWORD64 R13;
  DWORD64 R14;
  DWORD64 R15;
  DWORD64 Rip;
  union {
    XMM_SAVE_AREA32 FltSave;
    NEON128         Q[16];
    ULONGLONG       D[32];
    struct {
      M128A Header[2];
      M128A Legacy[8];
      M128A Xmm0;
      M128A Xmm1;
      M128A Xmm2;
      M128A Xmm3;
      M128A Xmm4;
      M128A Xmm5;
      M128A Xmm6;
      M128A Xmm7;
      M128A Xmm8;
      M128A Xmm9;
      M128A Xmm10;
      M128A Xmm11;
      M128A Xmm12;
      M128A Xmm13;
      M128A Xmm14;
      M128A Xmm15;
    } DUMMYSTRUCTNAME;
    DWORD           S[32];
  } DUMMYUNIONNAME;
  M128A   VectorRegister[26];
  DWORD64 VectorControl;
  DWORD64 DebugControl;
  DWORD64 LastBranchToRip;
  DWORD64 LastBranchFromRip;
  DWORD64 LastExceptionToRip;
  DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;
```

## Members

### Home Parameters (P1Home through P6Home)
Shadow space for the first six parameters in the x64 calling convention.

### ContextFlags
A bitmask indicating which parts of the context record are valid.

### MxCsr
The value of the MXCSR register.

### Segment Registers
- `SegCs` — Code segment selector
- `SegDs` — Data segment selector
- `SegEs` — Extra segment selector
- `SegFs` — FS segment selector (used for TEB on Windows)
- `SegGs` — GS segment selector
- `SegSs` — Stack segment selector

### EFlags
The processor flags register.

### Debug Registers
- `Dr0` through `Dr3` — Hardware breakpoint addresses
- `Dr6` — Debug status register
- `Dr7` — Debug control register

### General-Purpose Registers
- `Rax` — Accumulator
- `Rcx` — Counter
- `Rdx` — Data
- `Rbx` — Base
- `Rsp` — Stack pointer
- `Rbp` — Base pointer
- `Rsi` — Source index
- `Rdi` — Destination index
- `R8` through `R15` — Extended registers (x64 only)

### Rip
The instruction pointer (program counter).

### Floating-Point / SIMD State (DUMMYUNIONNAME)
- `FltSave` — x87 FPU and MMX state (`XMM_SAVE_AREA32`)
- `Q[16]` — NEON128 registers (ARM64)
- `Xmm0` through `Xmm15` — SSE registers

### AVX State
- `VectorRegister[26]` — AVX vector registers (Ymm0–Ymm15)
- `VectorControl` — AVX control register

### Last Branch / Exception Records
- `DebugControl` — Debug control register for PEBS/BTS
- `LastBranchToRip` — Last branch target address
- `LastBranchFromRip` — Last branch source address
- `LastExceptionToRip` — Last exception target address
- `LastExceptionFromRip` — Last exception source address

## Requirements

| Requirement | Value |
|---|---|
| Minimum supported client | Windows XP [desktop apps only] |
| Minimum supported server | Windows Server 2003 [desktop apps only] |
| Header | winnt.h (include Windows.h) |

## See also

- [Debugging Structures](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-debug_event_data)
- [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
- [GetXStateFeaturesMask](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-getxstatefeaturesmask)
- [SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
- [WOW64_CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-wow64_context)

Source: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
