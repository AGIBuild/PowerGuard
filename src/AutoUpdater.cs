using System.Text.Json;
using System.Text.RegularExpressions;

namespace PowerGuard;

internal sealed class AutoUpdater
{
    private const string LatestReleaseApiUrl = "https://api.github.com/repos/AGIBuild/PowerGuard/releases/latest";
    private readonly HttpClient _httpClient;

    public AutoUpdater(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();

        if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PowerGuard-Updater/1.0");
    }

    public async Task<UpdateCheckResult> CheckForUpdateAsync(Version currentVersion, CancellationToken cancellationToken = default)
    {
        try
        {
            using HttpResponseMessage response = await _httpClient.GetAsync(LatestReleaseApiUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
                return UpdateCheckResult.Failure($"Update API returned {(int)response.StatusCode}");

            string json = await response.Content.ReadAsStringAsync(cancellationToken);
            using JsonDocument doc = JsonDocument.Parse(json);

            JsonElement root = doc.RootElement;
            string? tagName = root.TryGetProperty("tag_name", out JsonElement tagElement)
                ? tagElement.GetString()
                : null;

            if (!TryParseTagVersion(tagName, out Version latestVersion))
                return UpdateCheckResult.Failure("Invalid release version tag.");

            if (latestVersion <= currentVersion)
                return UpdateCheckResult.NoUpdate(latestVersion);

            string? downloadUrl = FindMsiAssetUrl(root);
            if (string.IsNullOrWhiteSpace(downloadUrl))
                return UpdateCheckResult.Failure("No MSI asset found in latest release.");

            return UpdateCheckResult.UpdateAvailable(latestVersion, downloadUrl);
        }
        catch (Exception ex)
        {
            return UpdateCheckResult.Failure($"Update check failed: {ex.Message}");
        }
    }

    public async Task<string> DownloadInstallerAsync(string downloadUrl, CancellationToken cancellationToken = default)
    {
        string fileName = Path.GetFileName(new Uri(downloadUrl).LocalPath);
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = "PowerGuard-Update.msi";

        string updateDir = Path.Combine(Path.GetTempPath(), "PowerGuard", "updates");
        Directory.CreateDirectory(updateDir);

        string targetPath = Path.Combine(updateDir, fileName);
        using HttpResponseMessage response = await _httpClient.GetAsync(downloadUrl, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using Stream fileStream = File.Create(targetPath);
        await response.Content.CopyToAsync(fileStream, cancellationToken);

        return targetPath;
    }

    internal static bool TryParseTagVersion(string? tagName, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(tagName))
            return false;

        string normalized = tagName.Trim();
        if (normalized.StartsWith('v') || normalized.StartsWith('V'))
            normalized = normalized[1..];

        Match match = Regex.Match(normalized, @"^\d+\.\d+\.\d+(\.\d+)?");
        if (!match.Success)
            return false;

        if (!Version.TryParse(match.Value, out Version? parsed) || parsed is null)
            return false;

        version = parsed;
        return true;
    }

    private static string? FindMsiAssetUrl(JsonElement root)
    {
        if (!root.TryGetProperty("assets", out JsonElement assets) || assets.ValueKind != JsonValueKind.Array)
            return null;

        foreach (JsonElement asset in assets.EnumerateArray())
        {
            string? name = asset.TryGetProperty("name", out JsonElement nameElement)
                ? nameElement.GetString()
                : null;

            if (string.IsNullOrWhiteSpace(name) || !name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
                continue;

            string? url = asset.TryGetProperty("browser_download_url", out JsonElement urlElement)
                ? urlElement.GetString()
                : null;

            if (!string.IsNullOrWhiteSpace(url))
                return url;
        }

        return null;
    }
}

internal sealed record UpdateCheckResult(
    bool IsUpdateAvailable,
    Version? LatestVersion,
    string? DownloadUrl,
    string? ErrorMessage)
{
    public static UpdateCheckResult NoUpdate(Version latestVersion)
        => new(false, latestVersion, null, null);

    public static UpdateCheckResult UpdateAvailable(Version latestVersion, string downloadUrl)
        => new(true, latestVersion, downloadUrl, null);

    public static UpdateCheckResult Failure(string errorMessage)
        => new(false, null, null, errorMessage);
}
