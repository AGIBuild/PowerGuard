namespace PowerGuard.Tests;

public class AutoUpdaterTests
{
    [Theory]
    [InlineData("v1.2.3", "1.2.3")]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData("V2.0.1", "2.0.1")]
    [InlineData("v3.4.5-beta", "3.4.5")]
    public void TryParseTagVersion_ShouldParseSupportedFormats(string tag, string expected)
    {
        bool ok = AutoUpdater.TryParseTagVersion(tag, out Version version);

        Assert.True(ok);
        Assert.Equal(Version.Parse(expected), version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("foo")]
    [InlineData("v1")]
    [InlineData("v1.2")]
    public void TryParseTagVersion_ShouldRejectInvalidFormats(string tag)
    {
        bool ok = AutoUpdater.TryParseTagVersion(tag, out Version version);

        Assert.False(ok);
        Assert.Equal(new Version(0, 0, 0), version);
    }
}
