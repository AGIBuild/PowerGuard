using System.Runtime.InteropServices;
using PowerGuard.Properties;

namespace PowerGuard;

public class MainForm : Form
{
    private const int WM_QUERYENDSESSION = 0x0011;
    private const int WM_ENDSESSION = 0x0016;
    private const int WM_WTSSESSION_CHANGE = 0x02B1;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private readonly NotifyIcon _trayIcon;
    private readonly ContextMenuStrip _contextMenu;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ShutdownBlocker _blocker;
    private readonly List<ShutdownRecord> _attemptHistory = new();
    private bool _allowExit;

    public MainForm()
    {
        // Initialize shutdown blocker first
        _blocker = new ShutdownBlocker();
        _blocker.ShutdownAttempted += OnShutdownAttempted;

        // ===================================================================
        // Window setup: VISIBLE to Windows but INVISIBLE to user.
        // This is the #1 fix for AVD/RDS - the window MUST have WS_VISIBLE
        // for WM_QUERYENDSESSION delivery. SetVisibleCore(false) is REMOVED.
        // ===================================================================
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        Location = new Point(-32000, -32000); // off-screen
        Size = new Size(1, 1);

        // Build tray context menu
        _contextMenu = new ContextMenuStrip();

        _statusItem = new ToolStripMenuItem("Status: Blocking shutdown/restart/logoff")
        {
            Enabled = false
        };

        var historyItem = new ToolStripMenuItem("Show Attempts", null, OnShowHistory);
        var logItem = new ToolStripMenuItem("Open Log Folder", null, OnOpenLogFolder);
        var exitItem = new ToolStripMenuItem("Exit", null, OnExit);

        _contextMenu.Items.Add(_statusItem);
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add(historyItem);
        _contextMenu.Items.Add(logItem);
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add(exitItem);

        // Setup tray icon
        _trayIcon = new NotifyIcon
        {
            Icon = GetTrayIcon(),
            Text = "PowerGuard - Active",
            ContextMenuStrip = _contextMenu,
            Visible = true
        };
        _trayIcon.DoubleClick += OnShowHistory;

        // Start blocking immediately
        _blocker.StartBlocking("Shutdown/restart/logoff is blocked by policy");
    }

    /// <summary>
    /// WS_EX_TOOLWINDOW hides the window from Alt+Tab and taskbar
    /// while keeping it a real top-level window for WM_QUERYENDSESSION.
    /// </summary>
    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= WS_EX_TOOLWINDOW;
            return cp;
        }
    }

    // ===================================================================
    // DO NOT override SetVisibleCore(false)!
    // The window MUST be "visible" to Windows for WM_QUERYENDSESSION to
    // be delivered in RDS/AVD. This was the root cause of the failure.
    // ===================================================================

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        _blocker.AttachTo(this);
        ShutdownBlocker.Log($"MainForm handle created: 0x{Handle:X}");
    }

    protected override void WndProc(ref Message m)
    {
        switch (m.Msg)
        {
            case WM_QUERYENDSESSION:
                {
                    // Pass lParam to distinguish logoff (ENDSESSION_LOGOFF) from shutdown
                    bool allow = _blocker.HandleQueryEndSession(m.LParam);
                    m.Result = allow ? new IntPtr(1) : IntPtr.Zero;
                    return; // do NOT call base - we fully handle this
                }

            case WM_ENDSESSION:
                {
                    bool isEnding = m.WParam != IntPtr.Zero;
                    _blocker.HandleEndSession(isEnding, m.LParam);
                    if (isEnding && _blocker.IsBlocking)
                    {
                        // System insists on ending - do NOT pass to base; stay alive
                        m.Result = IntPtr.Zero;
                        return;
                    }
                    break;
                }

            case WM_WTSSESSION_CHANGE:
                {
                    _blocker.HandleSessionChange((int)m.WParam);
                    break;
                }
        }

        base.WndProc(ref m);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Block ALL close attempts except explicit exit via tray menu
        if (!_allowExit)
        {
            e.Cancel = true;
            ShutdownBlocker.Log($"OnFormClosing blocked: Reason={e.CloseReason}");
            return;
        }

        base.OnFormClosing(e);
    }

    private void OnShutdownAttempted(object? sender, ShutdownAttemptEventArgs e)
    {
        var record = new ShutdownRecord(e.AttemptTime, e.EventType) { WasAllowed = e.WasAllowed };
        _attemptHistory.Add(record);

        // Show notification asynchronously (avoid blocking WndProc)
        BeginInvoke(() =>
        {
            _trayIcon.BalloonTipTitle = $"{e.EventType} Blocked";
            _trayIcon.BalloonTipText = $"Blocked at {e.AttemptTime:HH:mm:ss}";
            _trayIcon.BalloonTipIcon = ToolTipIcon.Warning;
            _trayIcon.ShowBalloonTip(3000);
        });
    }

    private record ShutdownRecord(DateTime Time, string EventType)
    {
        public bool WasAllowed { get; set; }
    }

    private void OnShowHistory(object? sender, EventArgs e)
    {
        if (_attemptHistory.Count == 0)
        {
            MessageBox.Show("No shutdown/logoff attempts recorded.", "History",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var history = string.Join(Environment.NewLine,
            _attemptHistory.Select((r, i) =>
                $"{i + 1}. [{r.EventType}] {r.Time:yyyy-MM-dd HH:mm:ss} - {(r.WasAllowed ? "Allowed" : "Blocked")}"));

        MessageBox.Show($"Shutdown/Logoff attempts:\n\n{history}", "History",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private static void OnOpenLogFolder(object? sender, EventArgs e)
    {
        var logDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PowerGuard");

        if (!Directory.Exists(logDir))
            Directory.CreateDirectory(logDir);

        System.Diagnostics.Process.Start("explorer.exe", logDir);
    }

    private void OnExit(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "Are you sure you want to exit?\n\nThe system will no longer be protected from shutdown/logoff.",
            "Exit PowerGuard",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        if (result == DialogResult.Yes)
        {
            _allowExit = true;
            _blocker.StopBlocking();
            _trayIcon.Visible = false;
            Close();
        }
    }

    private static Icon CreateBlockIcon()
    {
        // Create a simple red shield icon programmatically
        var bitmap = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bitmap);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

        // Red shield shape
        using var brush = new SolidBrush(Color.FromArgb(220, 53, 69));
        var points = new Point[]
        {
            new(16, 2), new(28, 6), new(28, 14),
            new(16, 28), new(4, 14), new(4, 6)
        };
        g.FillPolygon(brush, points);

        // White X mark
        using var pen = new Pen(Color.White, 3);
        g.DrawLine(pen, 10, 10, 22, 20);
        g.DrawLine(pen, 22, 10, 10, 20);

        var hIcon = bitmap.GetHicon();
        try
        {
            using var temporaryIcon = Icon.FromHandle(hIcon);
            return (Icon)temporaryIcon.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    private static Icon GetTrayIcon()
    {
        var iconBytes = Resources.PowerGuard;
        if (iconBytes is { Length: > 0 })
        {
            using var iconStream = new MemoryStream(iconBytes);
            using var embeddedIcon = new Icon(iconStream);
            return (Icon)embeddedIcon.Clone();
        }

        using Icon? exeIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        if (exeIcon is not null)
            return (Icon)exeIcon.Clone();

        return CreateBlockIcon();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _blocker.Dispose();
            _trayIcon.Dispose();
            _contextMenu.Dispose();
        }
        base.Dispose(disposing);
    }
}
