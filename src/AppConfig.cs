using System.Text.Json;

namespace PowerGuard;

internal sealed class AppConfig
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public bool AutoUpdateEnabled { get; set; } = true;

    public bool RunAtStartupEnabled { get; set; }

    public int AntiIdleActivationSeconds { get; set; } = 1200;

    public static string ConfigDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PowerGuard");

    public static string ConfigPath => Path.Combine(ConfigDirectory, "config.json");

    public static AppConfig Load()
    {
        try
        {
            if (!File.Exists(ConfigPath))
                return new AppConfig();

            string content = File.ReadAllText(ConfigPath);
            AppConfig? config = JsonSerializer.Deserialize<AppConfig>(content, JsonOptions);
            return config ?? new AppConfig();
        }
        catch (Exception ex)
        {
            ShutdownBlocker.Log($"Config load failed: {ex.Message}");
            return new AppConfig();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDirectory);
            string content = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(ConfigPath, content);
        }
        catch (Exception ex)
        {
            ShutdownBlocker.Log($"Config save failed: {ex.Message}");
        }
    }
}
