namespace PowerGuard;

static class Program
{
    private static Mutex? _mutex;
    private static bool _ownsMutex;

    [STAThread]
    static void Main()
    {
        // Ensure single instance
        const string mutexName = "Global\\PowerGuard_SingleInstance";
        _mutex = new Mutex(initiallyOwned: true, mutexName, out bool createdNew);
        _ownsMutex = createdNew;

        if (!createdNew)
        {
            MessageBox.Show("PowerGuard is already running.", "PowerGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }
        finally
        {
            if (_ownsMutex)
                _mutex?.ReleaseMutex();

            _mutex?.Dispose();
        }
    }
}

