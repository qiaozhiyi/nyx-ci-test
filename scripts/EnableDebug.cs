// Enable SeDebugPrivilege in the current process token, then exec the given
// program with its arguments. The child inherits this token (with SeDebug now
// enabled), so PE-sieve can OpenProcess(PROCESS_VM_READ) on any process.
//   csc EnableDebug.cs  ->  EnableDebug.exe <program> [args...]
//
// SECURITY (CRITICAL-28): args[0] is treated as the program path and executed
// directly via ProcessStartInfo.FileName — it is NOT concatenated into a
// `cmd.exe /c` shell line, so shell metacharacters (`& | % > <` etc.) inside
// any argument can no longer break out into a separate command. Each remaining
// argument is quoted with WindowsArgvQuote and joined into Arguments, which
// .NET passes verbatim to CreateProcess (UseShellExecute=false). This matches
// the CRT argv-parsing rules that the child uses to split the line back into
// argv, so embedded spaces/quotes/backslashes round-trip correctly.
//
// Target: .NET Framework 4.x (compiled by Framework64\v4.0.30319\csc.exe, see
// deploy_detectors.ps1). No C# 8+ syntax, no ArgumentList (that API is .NET
// Core 3+ only).
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

internal static class EnableDebug {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool LookupPrivilegeValue(string sys, string name, ref long luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TP ns, int len, IntPtr prev, IntPtr relen);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [StructLayout(LayoutKind.Sequential, Pack=1)]
    struct TP { public int Count; public long Luid; public int Attr; }

    static bool Enable(string priv) {
        IntPtr htok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out htok)) return false;
        TP tp = new TP { Count=1, Luid=0, Attr=2 };
        if (!LookupPrivilegeValue(null, priv, ref tp.Luid)) return false;
        return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    // Quote a single argv element for the Windows command line using the same
    // rules the MSVC CRT uses to parse argv (backslashes are special only when
    // they precede a double-quote or the end of the string). Returns the quoted
    // token; the caller is responsible for joining tokens with spaces.
    static string WindowsArgvQuote(string arg) {
        if (arg == null) arg = "";
        // Fast path: no characters that need quoting.
        if (arg.Length > 0 && arg.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '\"' }) < 0) {
            return arg;
        }
        StringBuilder sb = new StringBuilder(arg.Length + 2);
        sb.Append('"');
        int backslashes = 0;
        foreach (char c in arg) {
            if (c == '\\') {
                backslashes++;
            } else if (c == '"') {
                // A double-quote must be escaped as \"; every run of backslashes
                // preceding it must be doubled (they now precede an escaped quote).
                for (int i = 0; i < backslashes * 2 + 1; i++) sb.Append('\\');
                sb.Append('"');
                backslashes = 0;
            } else {
                // Backslashes not preceding a quote are emitted literally.
                for (int i = 0; i < backslashes; i++) sb.Append('\\');
                backslashes = 0;
                sb.Append(c);
            }
        }
        // Trailing backslashes precede the closing quote, so double them.
        for (int i = 0; i < backslashes * 2; i++) sb.Append('\\');
        sb.Append('"');
        return sb.ToString();
    }

    static int Main(string[] args) {
        if (args.Length < 1) { Console.Error.WriteLine("usage: EnableDebug.exe <program> [args...]"); return 2; }
        if (!Enable("SeDebugPrivilege")) { Console.Error.WriteLine("SeDebug enable failed: " + Marshal.GetLastWin32Error()); }
        else { Console.WriteLine("SeDebugPrivilege enabled"); }

        // Run the program directly — no cmd.exe shim. FileName is args[0]
        // verbatim (the program path); Arguments is built by quoting each
        // remaining argv element. This closes the argument-injection vector
        // where an arg containing e.g. "& calc.exe &" used to execute calc
        // as SYSTEM (the wrapper historically ran via schtasks /RU SYSTEM).
        StringBuilder cmdline = new StringBuilder();
        for (int i = 1; i < args.Length; i++) {
            if (cmdline.Length > 0) cmdline.Append(' ');
            cmdline.Append(WindowsArgvQuote(args[i]));
        }

        var psi = new ProcessStartInfo {
            FileName = args[0],
            Arguments = cmdline.ToString(),
            UseShellExecute = false,
            CreateNoWindow = false,
        };

        Process p;
        try {
            p = Process.Start(psi);
        } catch (Exception e) {
            Console.Error.WriteLine("error launching '" + args[0] + "': " + e.Message);
            return 1;
        }
        if (p == null) { Console.Error.WriteLine("error: Process.Start returned null"); return 1; }
        p.WaitForExit();
        return p.ExitCode;
    }
}
