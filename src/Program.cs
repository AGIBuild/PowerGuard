namespace PowerGuard;

static class Program
{
    private static Mutex? _mutex;

    [STAThread]
    static void Main()
    {
        // Ensure single instance
        const string mutexName = "Global\\PowerGuard_SingleInstance";
        _mutex = new Mutex(true, mutexName, out bool createdNew);

        if (!createdNew)
        {
            MessageBox.Show("PowerGuard is already running.", "PowerGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());

        _mutex.ReleaseMutex();
        _mutex.Dispose();
    }
}

