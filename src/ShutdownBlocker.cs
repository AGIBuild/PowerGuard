using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace PowerGuard;

/// <summary>
/// Multi-layer shutdown/logoff blocker designed for Azure Virtual Desktop (AVD).
///
/// Blocking layers:
///   1. WM_QUERYENDSESSION -> return FALSE (via WndProc in MainForm)
///   2. SystemEvents.SessionEnding -> Cancel = true
///   3. ShutdownBlockReasonCreate (registered reason displayed by OS)
///   4. AbortSystemShutdown (cancel pending shutdown, requires privilege)
///   5. Anti-idle: keybd_event + SendInput + SetThreadExecutionState (prevent idle logoff)
///   6. WTS session notifications for RDS/AVD session change awareness
///   7. Periodic re-registration of block reason (guard against invalidation)
///   8. Registry: disable MaxIdleTime (nuclear option for RDS idle timeout)
/// </summary>
public partial class ShutdownBlocker : IDisposable
{
    #region P/Invoke

    [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShutdownBlockReasonCreate(IntPtr hWnd, string pwszReason);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShutdownBlockReasonDestroy(IntPtr hWnd);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessShutdownParameters(uint dwLevel, uint dwFlags);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AbortSystemShutdown(string? lpMachineName);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSRegisterSessionNotification(IntPtr hWnd, uint dwFlags);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSUnRegisterSessionNotification(IntPtr hWnd);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint SetThreadExecutionState(uint esFlags);

    [LibraryImport("user32.dll", SetLastError = true)]
    private static partial uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetLastInputInfo(ref LASTINPUTINFO plii);

    // Legacy keybd_event - more reliable than SendInput in some RDS scenarios
    [LibraryImport("user32.dll")]
    private static partial void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    // SetThreadExecutionState flags
    private const uint ES_CONTINUOUS = 0x80000000;
    private const uint ES_SYSTEM_REQUIRED = 0x00000001;
    private const uint ES_DISPLAY_REQUIRED = 0x00000002;

    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const byte VK_F15 = 0x7E;     // F15 key - harmless, no visible effect
    private const byte VK_SHIFT = 0x10;

    // INPUT struct with proper union layout via FieldOffset
    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUTUNION
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    private const uint INPUT_MOUSE = 0;
    private const uint INPUT_KEYBOARD = 1;
    private const uint MOUSEEVENTF_MOVE = 0x0001;

    #endregion

    #region WTS constants

    public const uint NOTIFY_FOR_THIS_SESSION = 0;

    public const int WTS_CONSOLE_CONNECT = 0x1;
    public const int WTS_CONSOLE_DISCONNECT = 0x2;
    public const int WTS_REMOTE_CONNECT = 0x3;
    public const int WTS_REMOTE_DISCONNECT = 0x4;
    public const int WTS_SESSION_LOGON = 0x5;
    public const int WTS_SESSION_LOGOFF = 0x6;
    public const int WTS_SESSION_LOCK = 0x7;
    public const int WTS_SESSION_UNLOCK = 0x8;

    public const uint ENDSESSION_LOGOFF = 0x80000000;

    #endregion

    #region Fields

    private bool _isBlocking;
    private bool _reasonRegistered;
    private string _blockReason = "PowerGuard is preventing shutdown";
    private bool _disposed;
    private IntPtr _hwnd;
    private Form? _form;
    private bool _wtsRegistered;
    private System.Threading.Timer? _refreshTimer;
    private System.Threading.Timer? _antiIdleTimer;
    private System.Threading.Timer? _registryWatchdogTimer;
    private int? _savedMaxIdleTime;             // original registry value to restore
    private int? _savedMaxDisconnectionTime;     // original registry value to restore
    private bool _registryModified;

    private static readonly string s_logDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PowerGuard");

    private static readonly string s_logPath = Path.Combine(s_logDir, "block.log");

    private const string TsRegKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    #endregion

    public event EventHandler<ShutdownAttemptEventArgs>? ShutdownAttempted;

    public bool IsBlocking => _isBlocking;

    public ShutdownBlocker()
    {
        // Highest shutdown priority for non-system processes (0x4FF).
        SetProcessShutdownParameters(0x4FF, 0);

        // .NET-level session ending handler (backup for WM_QUERYENDSESSION)
        SystemEvents.SessionEnding += OnSystemSessionEnding;
        SystemEvents.SessionSwitch += OnSystemSessionSwitch;

        Log("ShutdownBlocker initialised");
    }

    /// <summary>
    /// Attach to a real top-level window that has WS_VISIBLE set.
    /// CRITICAL: the window MUST be visible to Windows for WM_QUERYENDSESSION delivery in RDS/AVD.
    /// </summary>
    public void AttachTo(Form form)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(form);
        if (!form.IsHandleCreated)
            throw new InvalidOperationException("Form handle is not created yet.");

        _form = form;
        _hwnd = form.Handle;
        Log($"Attached to window handle 0x{_hwnd:X}");

        RegisterWtsNotification();
        TryRegisterReason();

        // Periodically re-register block reason (guards against OS clearing it)
        _refreshTimer = new System.Threading.Timer(
            _ => MarshalToUI(ForceReRegisterReason),
            null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public void StartBlocking(string? reason = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!string.IsNullOrEmpty(reason))
            _blockReason = reason;

        _isBlocking = true;
        TryRegisterReason();
        StartAntiIdle();
        TryDisableIdleTimeoutViaRegistry();
        StartRegistryWatchdog();

        Log("Blocking started");
    }

    public void StopBlocking()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _isBlocking = false;

        if (_reasonRegistered && _hwnd != IntPtr.Zero)
            ShutdownBlockReasonDestroy(_hwnd);

        _reasonRegistered = false;
        StopAntiIdle();
        StopRegistryWatchdog();
        TryRestoreIdleTimeoutRegistry();
        SetThreadExecutionState(ES_CONTINUOUS);

        Log("Blocking stopped");
    }

    /// <summary>
    /// Handle WM_QUERYENDSESSION. Return false to BLOCK.
    /// </summary>
    public bool HandleQueryEndSession(IntPtr lParam)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_isBlocking) return true;

        bool isLogoff = ((uint)(long)lParam & ENDSESSION_LOGOFF) != 0;
        string eventType = isLogoff ? "Logoff" : "Shutdown/Restart";
        Log($"WM_QUERYENDSESSION - {eventType} (lParam=0x{(long)lParam:X})");

        ForceReRegisterReason();
        TryAbortShutdown();

        RaiseAttempt(eventType);
        return false;
    }

    /// <summary>Handle WM_ENDSESSION.</summary>
    public void HandleEndSession(bool isEnding, IntPtr lParam)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        bool isLogoff = ((uint)(long)lParam & ENDSESSION_LOGOFF) != 0;
        Log($"WM_ENDSESSION - ending={isEnding}, logoff={isLogoff}");

        if (isEnding && _isBlocking)
        {
            TryAbortShutdown();
            ForceReRegisterReason();
        }
    }

    /// <summary>Handle WM_WTSSESSION_CHANGE (wParam = reason code).</summary>
    public void HandleSessionChange(int reason)
    {
        if (!_isBlocking) return;

        string desc = reason switch
        {
            WTS_SESSION_LOGOFF => "WTS_SESSION_LOGOFF",
            WTS_REMOTE_DISCONNECT => "WTS_REMOTE_DISCONNECT",
            WTS_CONSOLE_DISCONNECT => "WTS_CONSOLE_DISCONNECT",
            WTS_SESSION_LOCK => "WTS_SESSION_LOCK",
            WTS_SESSION_UNLOCK => "WTS_SESSION_UNLOCK",
            WTS_REMOTE_CONNECT => "WTS_REMOTE_CONNECT",
            _ => $"WTS_{reason}"
        };

        Log($"WM_WTSSESSION_CHANGE: {desc}");

        if (reason is WTS_SESSION_LOGOFF or WTS_REMOTE_DISCONNECT or WTS_CONSOLE_DISCONNECT)
        {
            TryAbortShutdown();
            ForceReRegisterReason();
            RaiseAttempt(desc);
        }
    }

    #region Anti-idle (prevent idle-triggered auto-logoff in AVD)

    private void StartAntiIdle()
    {
        // Prevent system sleep/idle (insufficient alone for RDS but still useful)
        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);

        // Run anti-idle every 30 seconds with multi-method approach
        _antiIdleTimer?.Dispose();
        _antiIdleTimer = new System.Threading.Timer(
            _ => PerformAntiIdle(),
            null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));

        Log("Anti-idle started (30s interval, multi-method)");
    }

    private void StopAntiIdle()
    {
        _antiIdleTimer?.Dispose();
        _antiIdleTimer = null;
    }

    /// <summary>
    /// Multi-method anti-idle: uses 3 different input simulation techniques
    /// to ensure at least one resets the RDS idle timer.
    /// </summary>
    private static void PerformAntiIdle()
    {
        try
        {
            uint tickBefore = GetLastInputTick();

            // Method 1: keybd_event (legacy API, most reliable in RDS)
            keybd_event(VK_F15, 0, 0, UIntPtr.Zero);                // key down
            keybd_event(VK_F15, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);  // key up

            uint tickAfterKeybd = GetLastInputTick();

            // Method 2: SendInput with keyboard (modern API)
            var kbInputs = new INPUT[2];
            kbInputs[0].type = INPUT_KEYBOARD;
            kbInputs[0].u.ki = new KEYBDINPUT { wVk = VK_SHIFT, dwFlags = 0 };
            kbInputs[1].type = INPUT_KEYBOARD;
            kbInputs[1].u.ki = new KEYBDINPUT { wVk = VK_SHIFT, dwFlags = KEYEVENTF_KEYUP };
            uint kbResult = SendInput(2, kbInputs, Marshal.SizeOf<INPUT>());

            uint tickAfterKbSend = GetLastInputTick();

            // Method 3: SendInput with mouse movement
            var mouseInputs = new INPUT[2];
            mouseInputs[0].type = INPUT_MOUSE;
            mouseInputs[0].u.mi = new MOUSEINPUT { dx = 1, dy = 0, dwFlags = MOUSEEVENTF_MOVE };
            mouseInputs[1].type = INPUT_MOUSE;
            mouseInputs[1].u.mi = new MOUSEINPUT { dx = -1, dy = 0, dwFlags = MOUSEEVENTF_MOVE };
            uint mouseResult = SendInput(2, mouseInputs, Marshal.SizeOf<INPUT>());

            uint tickAfterMouse = GetLastInputTick();

            // Method 4: Refresh execution state
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);

            Log($"AntiIdle: before={tickBefore}, afterKeybd={tickAfterKeybd}, " +
                $"afterKbSend={tickAfterKbSend}(ret={kbResult}), " +
                $"afterMouse={tickAfterMouse}(ret={mouseResult}), " +
                $"idle={(Environment.TickCount - tickAfterMouse)}ms");
        }
        catch (Exception ex)
        {
            Log($"AntiIdle error: {ex.Message}");
        }
    }

    private static uint GetLastInputTick()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        return GetLastInputInfo(ref info) ? info.dwTime : 0;
    }

    #endregion

    #region Registry-based idle timeout disable

    /// <summary>
    /// Attempt to set MaxIdleTime=0 and MaxDisconnectionTime=0 in the Terminal Services
    /// policy registry key. This directly prevents the RDS session host from enforcing
    /// idle timeout and disconnection timeout.
    /// Requires write access to HKLM (admin or appropriate permissions).
    /// </summary>
    private void TryDisableIdleTimeoutViaRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(TsRegKey, writable: true);
            if (key is null)
            {
                Log("Registry: TS key not found, skipping timeout disable");
                return;
            }

            // Disable MaxIdleTime
            TrySetRegistryTimeout(key, "MaxIdleTime", ref _savedMaxIdleTime);

            // Disable MaxDisconnectionTime
            TrySetRegistryTimeout(key, "MaxDisconnectionTime", ref _savedMaxDisconnectionTime);

            if (_savedMaxIdleTime.HasValue || _savedMaxDisconnectionTime.HasValue)
                _registryModified = true;
        }
        catch (UnauthorizedAccessException)
        {
            Log("Registry: no admin access, cannot modify timeouts (non-fatal)");
        }
        catch (Exception ex)
        {
            Log($"Registry: failed to modify timeouts: {ex.Message}");
        }
    }

    private static void TrySetRegistryTimeout(RegistryKey key, string valueName, ref int? savedValue)
    {
        var currentValue = key.GetValue(valueName);
        if (currentValue is int intVal && intVal > 0)
        {
            savedValue = intVal;
            key.SetValue(valueName, 0, RegistryValueKind.DWord);
            Log($"Registry: {valueName} changed from {intVal} to 0");
        }
        else if (currentValue is int zeroVal && zeroVal == 0)
        {
            Log($"Registry: {valueName} already 0, no change needed");
        }
        else
        {
            Log($"Registry: {valueName} value is {currentValue ?? "null"}, skipping");
        }
    }

    /// <summary>Restore original MaxIdleTime and MaxDisconnectionTime when blocking is stopped.</summary>
    private void TryRestoreIdleTimeoutRegistry()
    {
        if (!_registryModified) return;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(TsRegKey, writable: true);
            if (key is not null)
            {
                TryRestoreRegistryTimeout(key, "MaxIdleTime", _savedMaxIdleTime);
                TryRestoreRegistryTimeout(key, "MaxDisconnectionTime", _savedMaxDisconnectionTime);
            }
            _registryModified = false;
        }
        catch (Exception ex)
        {
            Log($"Registry: failed to restore timeouts: {ex.Message}");
        }
    }

    private static void TryRestoreRegistryTimeout(RegistryKey key, string valueName, int? savedValue)
    {
        if (savedValue.HasValue)
        {
            key.SetValue(valueName, savedValue.Value, RegistryValueKind.DWord);
            Log($"Registry: {valueName} restored to {savedValue.Value}");
        }
    }

    /// <summary>
    /// Start a watchdog timer that checks every 60 seconds whether Group Policy or
    /// other processes have overwritten MaxIdleTime/MaxDisconnectionTime back to non-zero.
    /// If detected, immediately re-set them to 0.
    /// </summary>
    private void StartRegistryWatchdog()
    {
        _registryWatchdogTimer?.Dispose();
        _registryWatchdogTimer = new System.Threading.Timer(
            _ => CheckAndReEnforceRegistryTimeouts(),
            null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));

        Log("Registry watchdog started (60s interval)");
    }

    private void StopRegistryWatchdog()
    {
        _registryWatchdogTimer?.Dispose();
        _registryWatchdogTimer = null;
    }

    private void CheckAndReEnforceRegistryTimeouts()
    {
        if (!_isBlocking) return;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(TsRegKey, writable: true);
            if (key is null) return;

            ReEnforceIfChanged(key, "MaxIdleTime", ref _savedMaxIdleTime);
            ReEnforceIfChanged(key, "MaxDisconnectionTime", ref _savedMaxDisconnectionTime);
        }
        catch (Exception ex)
        {
            Log($"Registry watchdog error: {ex.Message}");
        }
    }

    /// <summary>
    /// Check a single registry timeout value. If it was reset to non-zero by GPO or
    /// another process, save the new value and set it back to 0.
    /// </summary>
    private static void ReEnforceIfChanged(RegistryKey key, string valueName, ref int? savedValue)
    {
        var currentValue = key.GetValue(valueName);
        if (currentValue is int intVal && intVal > 0)
        {
            // Update saved value if the new value differs (GPO may have changed it)
            if (!savedValue.HasValue || savedValue.Value != intVal)
                savedValue = intVal;

            key.SetValue(valueName, 0, RegistryValueKind.DWord);
            Log($"Registry watchdog: {valueName} was reset to {intVal} by external process, re-enforced to 0");
        }
    }

    #endregion

    #region SystemEvents handlers

    private void OnSystemSessionEnding(object sender, SessionEndingEventArgs e)
    {
        if (!_isBlocking) return;

        string eventType = e.Reason switch
        {
            SessionEndReasons.Logoff => "SystemEvents.Logoff",
            SessionEndReasons.SystemShutdown => "SystemEvents.Shutdown",
            _ => "SystemEvents.Unknown"
        };

        Log($"SessionEnding event: {eventType}");

        e.Cancel = true;
        TryAbortShutdown();
        MarshalToUI(ForceReRegisterReason);

        RaiseAttempt(eventType);
    }

    private void OnSystemSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        Log($"SessionSwitch event: {e.Reason}");

        if (!_isBlocking) return;

        if (e.Reason is SessionSwitchReason.SessionLogoff
            or SessionSwitchReason.ConsoleDisconnect
            or SessionSwitchReason.RemoteDisconnect)
        {
            TryAbortShutdown();
            MarshalToUI(ForceReRegisterReason);
        }
    }

    #endregion

    #region Private helpers

    private void RegisterWtsNotification()
    {
        if (_wtsRegistered || _hwnd == IntPtr.Zero) return;

        try
        {
            _wtsRegistered = WTSRegisterSessionNotification(_hwnd, NOTIFY_FOR_THIS_SESSION);
            Log($"WTS notification registered: {_wtsRegistered}");
        }
        catch (Exception ex)
        {
            Log($"WTS registration failed: {ex.Message}");
        }
    }

    private void TryRegisterReason()
    {
        if (!_isBlocking || _reasonRegistered || _hwnd == IntPtr.Zero) return;
        _reasonRegistered = ShutdownBlockReasonCreate(_hwnd, _blockReason);
        Log($"Block reason registered: {_reasonRegistered}");
    }

    private void ForceReRegisterReason()
    {
        if (!_isBlocking || _hwnd == IntPtr.Zero) return;

        if (_reasonRegistered)
        {
            ShutdownBlockReasonDestroy(_hwnd);
            _reasonRegistered = false;
        }

        _reasonRegistered = ShutdownBlockReasonCreate(_hwnd, _blockReason);
    }

    private void TryAbortShutdown()
    {
        try
        {
            bool ok = AbortSystemShutdown(null);
            Log($"AbortSystemShutdown: {ok} (err={Marshal.GetLastPInvokeError()})");
        }
        catch (Exception ex)
        {
            Log($"AbortSystemShutdown exception: {ex.Message}");
        }
    }

    private void RaiseAttempt(string eventType)
    {
        ShutdownAttempted?.Invoke(this,
            new ShutdownAttemptEventArgs(DateTime.Now, eventType) { WasAllowed = false });
    }

    private void MarshalToUI(Action action)
    {
        try
        {
            if (_form is { IsHandleCreated: true, IsDisposed: false })
            {
                if (_form.InvokeRequired)
                    _form.BeginInvoke(action);
                else
                    action();
            }
            else
            {
                action();
            }
        }
        catch
        {
            // best effort
        }
    }

    internal static void Log(string message)
    {
        try
        {
            if (!Directory.Exists(s_logDir))
                Directory.CreateDirectory(s_logDir);

            File.AppendAllText(s_logPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
        }
        catch
        {
            // best-effort
        }
    }

    #endregion

    #region Dispose

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;

        if (disposing)
        {
            _refreshTimer?.Dispose();
            _antiIdleTimer?.Dispose();
            _registryWatchdogTimer?.Dispose();

            SystemEvents.SessionEnding -= OnSystemSessionEnding;
            SystemEvents.SessionSwitch -= OnSystemSessionSwitch;

            if (_wtsRegistered && _hwnd != IntPtr.Zero)
            {
                try { WTSUnRegisterSessionNotification(_hwnd); }
                catch { /* best effort */ }
            }

            try { StopBlocking(); }
            catch { /* best effort */ }
        }

        Log("ShutdownBlocker disposed");
    }

    ~ShutdownBlocker() => Dispose(false);

    #endregion
}

public class ShutdownAttemptEventArgs : EventArgs
{
    public DateTime AttemptTime { get; }
    public string EventType { get; }
    public bool WasAllowed { get; internal set; }

    public ShutdownAttemptEventArgs(DateTime attemptTime, string eventType = "Unknown")
    {
        AttemptTime = attemptTime;
        EventType = eventType;
    }
}
