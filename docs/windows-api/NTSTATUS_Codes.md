# [MS-ERREF]: NTSTATUS Values

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

> Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

## Success Codes (0x00000000 – 0x00000367)

| Hex | Name | Description |
|---|---|---|
| 0x00000000 | STATUS_SUCCESS / STATUS_WAIT_0 | The operation completed successfully |
| 0x00000001 | STATUS_WAIT_1 | WaitAny: one dispatcher object signaled |
| 0x00000002 | STATUS_WAIT_2 | WaitAny: one dispatcher object signaled |
| 0x00000003 | STATUS_WAIT_3 | WaitAny: one dispatcher object signaled |
| 0x0000003F | STATUS_WAIT_63 | WaitAny: one dispatcher object signaled |
| 0x00000080 | STATUS_ABANDONED / STATUS_ABANDONED_WAIT_0 | Caller attempted to wait for an abandoned mutex |
| 0x000000BF | STATUS_ABANDONED_WAIT_63 | Caller attempted to wait for an abandoned mutex |
| 0x000000C0 | STATUS_USER_APC | A user-mode APC was delivered before interval expired |
| 0x00000101 | STATUS_ALERTED | The delay completed because the thread was alerted |
| 0x00000102 | STATUS_TIMEOUT | The given Timeout interval expired |
| 0x00000103 | STATUS_PENDING | The operation that was requested is pending completion |
| 0x00000104 | STATUS_REPARSE | A reparse should be performed (symbolic link) |
| 0x00000105 | STATUS_MORE_ENTRIES | Returned by enumeration APIs to indicate more info available |
| 0x00000106 | STATUS_NOT_ALL_ASSIGNED | Not all privileges or groups are assigned to caller |
| 0x00000107 | STATUS_SOME_NOT_MAPPED | Some information to be translated has not been translated |
| 0x00000108 | STATUS_OPLOCK_BREAK_IN_PROGRESS | An oplock break is underway |
| 0x00000109 | STATUS_VOLUME_MOUNTED | A new volume has been mounted |
| 0x0000010A | STATUS_RXACT_COMMITTED | Transaction commit completed |
| 0x0000010B | STATUS_NOTIFY_CLEANUP | Notify change request completed |
| 0x0000010C | STATUS_NOTIFY_ENUM_DIR | Notify change request completing, info not returned |
| 0x0000010D | STATUS_NO_QUOTAS_FOR_ACCOUNT | No system quota limits set for this account |
| 0x0000010E | STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED | Connection failed on primary transport |
| 0x00000110 | STATUS_PAGE_FAULT_TRANSITION | The page fault was a transition fault |
| 0x00000111 | STATUS_PAGE_FAULT_DEMAND_ZERO | The page fault was a demand zero fault |
| 0x00000112 | STATUS_PAGE_FAULT_COPY_ON_WRITE | The page fault was a copy-on-write fault |
| 0x00000113 | STATUS_PAGE_FAULT_GUARD_PAGE | The page fault was a guard page fault |
| 0x00000114 | STATUS_PAGE_FAULT_PAGING_FILE | Page fault satisfied by reading from secondary storage |
| 0x00000115 | STATUS_CACHE_PAGE_LOCKED | The cached page was locked during operation |
| 0x00000116 | STATUS_CRASH_DUMP | The crash dump exists in a paging file |
| 0x00000117 | STATUS_BUFFER_ALL_ZEROS | The specified buffer contains all zeros |
| 0x00000118 | STATUS_REPARSE_OBJECT | A reparse should be performed (symbolic link) |
| 0x00000119 | STATUS_RESOURCE_REQUIREMENTS_CHANGED | Device resource requirements have changed |
| 0x00000122 | STATUS_NOTHING_TO_TERMINATE | Process has no threads to terminate |
| 0x00000123 | STATUS_PROCESS_NOT_IN_JOB | Specified process is not part of a job |
| 0x00000124 | STATUS_PROCESS_IN_JOB | Specified process is part of a job |
| 0x0000012A | STATUS_FILE_LOCKED_WITH_ONLY_READERS | File locked, all users can only read |
| 0x0000012B | STATUS_FILE_LOCKED_WITH_WRITERS | File locked, at least one user can write |
| 0x00000367 | STATUS_WAIT_FOR_OPLOCK | Operation blocked, waiting for oplock |

## Debugger Success Codes

| Hex | Name | Description |
|---|---|---|
| 0x00010001 | DBG_EXCEPTION_HANDLED | Debugger handled the exception |
| 0x00010002 | DBG_CONTINUE | The debugger continued |

## Informational Codes (0x40000000 – 0x40230001)

| Hex | Name | Description |
|---|---|---|
| 0x40000000 | STATUS_OBJECT_NAME_EXISTS | Object name already exists |
| 0x40000001 | STATUS_THREAD_WAS_SUSPENDED | Thread was suspended during termination |
| 0x40000003 | STATUS_IMAGE_NOT_AT_BASE | Image could not be mapped at specified address |
| 0x40000005 | STATUS_SEGMENT_NOTIFICATION | VDM loading/unloading MS-DOS segment |
| 0x4000000E | STATUS_IMAGE_MACHINE_TYPE_MISMATCH | Image is for a different machine type |
| 0x40000020 | STATUS_WX86_EXCEPTION_CONTINUE | Win32 x86 emulation exception |
| 0x40000021 | STATUS_WX86_EXCEPTION_LASTCHANCE | Win32 x86 emulation exception |
| 0x40000022 | STATUS_WX86_EXCEPTION_CHAIN | Win32 x86 emulation exception |
| 0x4000002A | STATUS_HIBERNATED | System put into hibernation |
| 0x4000002B | STATUS_RESUME_HIBERNATION | System resumed from hibernation |

## Debugger Informational Codes

| Hex | Name | Description |
|---|---|---|
| 0x40010001 | DBG_REPLY_LATER | Debugger will reply later |
| 0x40010002 | DBG_UNABLE_TO_PROVIDE_HANDLE | Debugger cannot provide a handle |
| 0x40010003 | DBG_TERMINATE_THREAD | Debugger terminated the thread |
| 0x40010004 | DBG_TERMINATE_PROCESS | Debugger terminated the process |
| 0x40010005 | DBG_CONTROL_C | Debugger obtained control of C |
| 0x40010006 | DBG_PRINTEXCEPTION_C | Debugger printed exception on control C |
| 0x40010007 | DBG_RIPEXCEPTION | Debugger received a RIP exception |
| 0x40010008 | DBG_CONTROL_BREAK | Debugger received a control break |
| 0x40010009 | DBG_COMMAND_EXCEPTION | Debugger command communication exception |

## Warning Codes (0x80000000 – 0x80210002)

| Hex | Name | Description |
|---|---|---|
| 0x80000001 | STATUS_GUARD_PAGE_VIOLATION | Guard page exception — end of data structure accessed |
| 0x80000002 | STATUS_DATATYPE_MISALIGNMENT | Alignment fault — data type misalignment detected |
| 0x80000003 | STATUS_BREAKPOINT | Breakpoint reached |
| **0x80000004** | **STATUS_SINGLE_STEP** | **{EXCEPTION} Single Step — a single step or trace operation has just been completed** |
| 0x80000005 | STATUS_BUFFER_OVERFLOW | Data was too large for the buffer |
| 0x80000006 | STATUS_NO_MORE_FILES | No more files match the specification |
| 0x80000007 | STATUS_WAKE_SYSTEM_DEBUGGER | Kernel debugger awakened by interrupt |
| 0x8000000D | STATUS_PARTIAL_COPY | Not all requested bytes could be copied (protection conflicts) |
| 0x8000001A | STATUS_NO_MORE_ENTRIES | No more entries from enumeration |
| 0x80000026 | STATUS_LONGJUMP | A long jump has been executed |
| 0x80000029 | STATUS_UNWIND_CONSOLIDATE | Frame consolidation executed |

## Debugger Warning Codes

| Hex | Name | Description |
|---|---|---|
| 0x80010001 | DBG_EXCEPTION_NOT_HANDLED | Debugger did not handle the exception |

## Error Codes (0xC0000000 – 0xC0000099+)

| Hex | Name | Description |
|---|---|---|
| 0xC0000001 | STATUS_UNSUCCESSFUL | The requested operation was unsuccessful |
| 0xC0000002 | STATUS_NOT_IMPLEMENTED | The requested operation is not implemented |
| 0xC0000003 | STATUS_INVALID_INFO_CLASS | Invalid information class for the specified object |
| 0xC0000004 | STATUS_INFO_LENGTH_MISMATCH | Information record length doesn't match required |
| 0xC0000005 | STATUS_ACCESS_VIOLATION | Instruction referenced inaccessible memory |
| 0xC0000006 | STATUS_IN_PAGE_ERROR | Required data not placed into memory (I/O error) |
| 0xC0000007 | STATUS_PAGEFILE_QUOTA | Page file quota exhausted |
| 0xC0000008 | STATUS_INVALID_HANDLE | An invalid HANDLE was specified |
| 0xC000000D | STATUS_INVALID_PARAMETER | An invalid parameter was passed |
| 0xC0000010 | STATUS_INVALID_DEVICE_REQUEST | Not a valid operation for the target device |
| 0xC0000011 | STATUS_END_OF_FILE | End-of-file marker reached |
| 0xC0000017 | STATUS_NO_MEMORY | Not enough virtual memory or paging file quota |
| 0xC000001D | STATUS_ILLEGAL_INSTRUCTION | Attempted to execute illegal instruction |
| 0xC0000022 | STATUS_ACCESS_DENIED | Process requested access but was not granted |
| 0xC0000023 | STATUS_BUFFER_TOO_SMALL | Buffer too small to contain the entry |
| 0xC0000024 | STATUS_OBJECT_TYPE_MISMATCH | Mismatch between required and specified object type |
| 0xC0000025 | STATUS_NONCONTINUABLE_EXCEPTION | Windows cannot continue from this exception |
| 0xC0000026 | STATUS_INVALID_DISPOSITION | Invalid exception disposition returned by handler |
| 0xC0000034 | STATUS_OBJECT_NAME_NOT_FOUND | The object name is not found |
| 0xC000003A | STATUS_OBJECT_PATH_NOT_FOUND | The path does not exist |
| 0xC0000043 | STATUS_SHARING_VIOLATION | File cannot be opened (share access conflict) |
| 0xC000007B | STATUS_INVALID_IMAGE_FORMAT | Bad image — not designed to run on Windows or contains error |
| 0xC000008C | STATUS_ARRAY_BOUNDS_EXCEEDED | Array bounds exceeded |
| 0xC000008D | STATUS_FLOAT_DENORMAL_OPERAND | Floating-point denormal operand |
| 0xC000008E | STATUS_FLOAT_DIVIDE_BY_ZERO | Floating-point division by zero |
| 0xC000008F | STATUS_FLOAT_INEXACT_RESULT | Floating-point inexact result |
| 0xC0000090 | STATUS_FLOAT_INVALID_OPERATION | Floating-point invalid operation |
| 0xC0000091 | STATUS_FLOAT_OVERFLOW | Floating-point overflow |
| 0xC0000092 | STATUS_FLOAT_STACK_CHECK | Floating-point stack check |
| 0xC0000093 | STATUS_FLOAT_UNDERFLOW | Floating-point underflow |
| 0xC0000094 | STATUS_INTEGER_DIVIDE_BY_ZERO | Integer division by zero |
| 0xC0000095 | STATUS_INTEGER_OVERFLOW | Integer overflow |
| 0xC0000096 | STATUS_PRIVILEGED_INSTRUCTION | Privileged instruction |

---

**Note**: This is a partial extraction of commonly used NTSTATUS codes from the full [MS-ERREF] specification. The full specification contains hundreds of additional codes. Refer to the source link above for the complete list.
