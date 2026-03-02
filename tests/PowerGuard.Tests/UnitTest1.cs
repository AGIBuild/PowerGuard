namespace PowerGuard.Tests;

public class ShutdownBlockerConstantsTests
{
    [Fact]
    public void EndSessionLogoffFlag_ShouldMatchWindowsValue()
    {
        Assert.Equal(0x80000000u, ShutdownBlocker.ENDSESSION_LOGOFF);
    }

    [Fact]
    public void SessionChangeConstants_ShouldMatchExpectedValues()
    {
        Assert.Equal(0x5, ShutdownBlocker.WTS_SESSION_LOGON);
        Assert.Equal(0x6, ShutdownBlocker.WTS_SESSION_LOGOFF);
        Assert.Equal(0x7, ShutdownBlocker.WTS_SESSION_LOCK);
        Assert.Equal(0x8, ShutdownBlocker.WTS_SESSION_UNLOCK);
    }

    [Fact]
    public void SessionConnectAndDisconnectConstants_ShouldBeDistinct()
    {
        var values = new HashSet<int>
        {
            ShutdownBlocker.WTS_CONSOLE_CONNECT,
            ShutdownBlocker.WTS_CONSOLE_DISCONNECT,
            ShutdownBlocker.WTS_REMOTE_CONNECT,
            ShutdownBlocker.WTS_REMOTE_DISCONNECT
        };

        Assert.Equal(4, values.Count);
    }
}
