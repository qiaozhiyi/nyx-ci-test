// Enable SeDebugPrivilege in the current process token, then exec the given
// command line. The child inherits this token (with SeDebug now enabled), so
// PE-sieve can OpenProcess(PROCESS_VM_READ) on any process.
//   csc EnableDebug.cs  ->  EnableDebug.exe <command line...>
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal static class EnableDebug {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool LookupPrivilegeValue(string sys, string name, ref long luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TP ns, int len, IntPtr prev, IntPtr relen);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool CreateProcessAsUser(IntPtr hToken, string app, string cmd, IntPtr pa, IntPtr ta, bool inh, uint flags, IntPtr env, string dir, [In] ref SI si, out PI pi);

    [StructLayout(LayoutKind.Sequential, Pack=1)]
    struct TP { public int Count; public long Luid; public int Attr; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
    struct SI { public int cb; public IntPtr reserved; public string desktop; public string title; public uint x, y, xs, ys, xc, yc, fill, flags; public short sw, cb2; public IntPtr reserved2; public IntPtr stdin, stdout, stderr; }
    [StructLayout(LayoutKind.Sequential)]
    struct PI { public IntPtr hProc; public IntPtr hThread; public uint pid; public uint tid; }

    static bool Enable(string priv) {
        IntPtr htok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out htok)) return false;
        TP tp = new TP { Count=1, Luid=0, Attr=2 };
        if (!LookupPrivilegeValue(null, priv, ref tp.Luid)) return false;
        return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    static int Main(string[] args) {
        if (args.Length < 1) { Console.Error.WriteLine("usage: EnableDebug.exe <cmd> [args...]"); return 2; }
        if (!Enable("SeDebugPrivilege")) { Console.Error.WriteLine("SeDebug enable failed: " + Marshal.GetLastWin32Error()); }
        else { Console.WriteLine("SeDebugPrivilege enabled"); }

        // Exec the rest of the args as one command line.
        string app = args[0];
        var sb = new System.Text.StringBuilder();
        for (int i = 1; i < args.Length; i++) { if (i > 1) sb.Append(' '); sb.Append('"'); sb.Append(args[i]); sb.Append('"'); }
        string cmdline = app + " " + sb.ToString();

        var psi = new ProcessStartInfo {
            FileName = "cmd.exe",
            Arguments = "/c " + cmdline,
            UseShellExecute = false,
            CreateNoWindow = false,
        };
        var p = Process.Start(psi);
        p.WaitForExit();
        return p.ExitCode;
    }
}
