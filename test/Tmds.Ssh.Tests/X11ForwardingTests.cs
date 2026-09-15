using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Tmds.Ssh.Tests;

public class X11DisplayTests
{
    [Theory]
    [InlineData(":0", null, null, 0, 0)]
    [InlineData(":10.2", null, null, 10, 2)]
    [InlineData("unix:1", null, null, 1, 0)]
    [InlineData("localhost:10.0", "localhost", null, 10, 0)]
    [InlineData("host.example.com:3", "host.example.com", null, 3, 0)]
    [InlineData("192.168.1.5:0.1", "192.168.1.5", null, 0, 1)]
    [InlineData("::1:0", "::1", null, 0, 0)]
    [InlineData("[::1]:0", "::1", null, 0, 0)]
    [InlineData("/private/tmp/com.apple.launchd.abc/org.xquartz:0", null, "/private/tmp/com.apple.launchd.abc/org.xquartz:0", 0, 0)]
    [InlineData("/private/tmp/com.apple.launchd.abc/org.xquartz:0.1", null, "/private/tmp/com.apple.launchd.abc/org.xquartz:0", 0, 1)]
    public void Parse(string name, string? host, string? socketPath, int displayNumber, int screenNumber)
    {
        Assert.True(X11Display.TryParse(name, out X11Display? display));
        Assert.Equal(name, display.Name);
        Assert.Equal(host, display.Host);
        Assert.Equal(socketPath, display.SocketPath);
        Assert.Equal(displayNumber, display.DisplayNumber);
        Assert.Equal(screenNumber, display.ScreenNumber);
    }

    [Theory]
    [InlineData("")]
    [InlineData("foo")]
    [InlineData(":")]
    [InlineData(":a")]
    [InlineData(":0.")]
    [InlineData(":0.x")]
    [InlineData(":-1")]
    [InlineData(":60000")]
    public void ParseInvalid(string name)
    {
        Assert.False(X11Display.TryParse(name, out _));
    }

    [Theory]
    [InlineData(":0", ":0")]
    [InlineData("localhost:10.0", "unix:10.0")]
    [InlineData("host:1", "host:1")]
    [InlineData("/tmp/launchd/org.xquartz:0", ":0")]
    public void XAuthDisplayName(string name, string expected)
    {
        Assert.True(X11Display.TryParse(name, out X11Display? display));
        Assert.Equal(expected, display.XAuthDisplayName);
    }
}

public class XAuthorityTests
{
    private static readonly byte[] Cookie = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

    [Fact]
    public void FindsCookieForDisplayNumberAndAddress()
    {
        byte[] content = Serialize(
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii("otherhost"), "0", XAuthority.MitMagicCookie, [9, 9]),
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii("myhost"), "1", XAuthority.MitMagicCookie, [8, 8]),
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii("myhost"), "0", "XDM-AUTHORIZATION-1", [7, 7]),
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii("myhost"), "0", XAuthority.MitMagicCookie, Cookie));

        List<XAuthority.Entry> entries = XAuthority.ParseEntries(content);

        Assert.Equal(4, entries.Count);
        Assert.Equal(Cookie, XAuthority.FindCookie(entries, 0, [(XAuthority.FamilyLocal, Ascii("myhost"))]));
        Assert.Equal([8, 8], XAuthority.FindCookie(entries, 1, [(XAuthority.FamilyLocal, Ascii("myhost"))]));
        Assert.Null(XAuthority.FindCookie(entries, 2, [(XAuthority.FamilyLocal, Ascii("myhost"))]));
        Assert.Null(XAuthority.FindCookie(entries, 0, [(XAuthority.FamilyInternet, [127, 0, 0, 1])]));
    }

    [Fact]
    public void FindsCookieForInternetAddress()
    {
        byte[] content = Serialize(
            new XAuthority.Entry(XAuthority.FamilyInternet, [10, 0, 0, 1], "3", XAuthority.MitMagicCookie, [9, 9]),
            new XAuthority.Entry(XAuthority.FamilyInternet, [127, 0, 0, 1], "3", XAuthority.MitMagicCookie, Cookie));

        Assert.Equal(Cookie, XAuthority.FindCookie(XAuthority.ParseEntries(content), 3, [(XAuthority.FamilyInternet, [127, 0, 0, 1])]));
    }

    [Fact]
    public void WildFamilyMatchesAnyAddress()
    {
        byte[] content = Serialize(
            new XAuthority.Entry(XAuthority.FamilyWild, [], "0", XAuthority.MitMagicCookie, Cookie));

        Assert.Equal(Cookie, XAuthority.FindCookie(XAuthority.ParseEntries(content), 0, [(XAuthority.FamilyLocal, Ascii("myhost"))]));
    }

    [Fact]
    public void ParseIgnoresTruncatedEntry()
    {
        byte[] content = Serialize(
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii("myhost"), "0", XAuthority.MitMagicCookie, Cookie),
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii("myhost"), "1", XAuthority.MitMagicCookie, Cookie));

        List<XAuthority.Entry> entries = XAuthority.ParseEntries(content.AsSpan(0, content.Length - 1));

        XAuthority.Entry entry = Assert.Single(entries);
        Assert.Equal("0", entry.Number);
    }

    [Fact]
    public async Task FindCookieAsyncUsesLocalHostNameForLocalDisplay()
    {
        using TempFile file = new TempFile(Path.GetTempFileName());
        File.WriteAllBytes(file.Path, Serialize(
            new XAuthority.Entry(XAuthority.FamilyLocal, Ascii(Dns.GetHostName()), "5", XAuthority.MitMagicCookie, Cookie)));
        Assert.True(X11Display.TryParse(":5.0", out X11Display? display));

        Assert.Equal(Cookie, await XAuthority.FindCookieAsync(file.Path, display, default));
    }

    [Fact]
    public async Task FindCookieAsyncReturnsNullForMissingFile()
    {
        Assert.True(X11Display.TryParse(":0", out X11Display? display));

        Assert.Null(await XAuthority.FindCookieAsync(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()), display, default));
    }

    internal static byte[] Serialize(params XAuthority.Entry[] entries)
    {
        using var stream = new MemoryStream();
        foreach (var entry in entries)
        {
            WriteUInt16(entry.Family);
            WriteBytes(entry.Address);
            WriteBytes(Ascii(entry.Number));
            WriteBytes(Ascii(entry.Name));
            WriteBytes(entry.Data);
        }
        return stream.ToArray();

        void WriteUInt16(int value)
        {
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)value);
            stream.Write(buffer);
        }

        void WriteBytes(byte[] value)
        {
            WriteUInt16(value.Length);
            stream.Write(value);
        }
    }

    private static byte[] Ascii(string value)
        => Encoding.ASCII.GetBytes(value);
}

public class X11AuthenticationTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ReplacesFakeCookie(bool bigEndian)
    {
        var forwarding = new X11Forwarding(NullLogger<SshClient>.Instance, default);
        X11Forwarding.Target otherTarget = forwarding.AddTarget(ParseDisplay(":1"), isTrusted: true, RandomNumberGenerator.GetBytes(16));
        byte[] cookie = RandomNumberGenerator.GetBytes(16);
        X11Forwarding.Target target = forwarding.AddTarget(ParseDisplay(":0"), isTrusted: true, cookie);
        byte[] setupMessage = CreateSetupMessage(bigEndian, XAuthority.MitMagicCookie, target.FakeCookie);

        Assert.Same(target, forwarding.Authenticate(setupMessage));

        Assert.Equal(cookie, GetAuthenticationData(setupMessage));
        Assert.NotEqual(otherTarget.FakeCookie, target.FakeCookie);
        Assert.Equal(Convert.ToHexString(target.FakeCookie).ToLowerInvariant(), target.FakeCookieHex);
    }

    [Fact]
    public void RejectsUnknownCookie()
    {
        var forwarding = new X11Forwarding(NullLogger<SshClient>.Instance, default);
        X11Forwarding.Target target = forwarding.AddTarget(ParseDisplay(":0"), isTrusted: true, RandomNumberGenerator.GetBytes(16));
        byte[] data = RandomNumberGenerator.GetBytes(16);
        byte[] setupMessage = CreateSetupMessage(bigEndian: false, XAuthority.MitMagicCookie, data);

        Assert.Null(forwarding.Authenticate(setupMessage));

        Assert.Equal(data, GetAuthenticationData(setupMessage));
    }

    [Fact]
    public void RejectsOtherProtocol()
    {
        var forwarding = new X11Forwarding(NullLogger<SshClient>.Instance, default);
        X11Forwarding.Target target = forwarding.AddTarget(ParseDisplay(":0"), isTrusted: true, RandomNumberGenerator.GetBytes(16));
        byte[] setupMessage = CreateSetupMessage(bigEndian: false, "XDM-AUTHORIZATION-1", target.FakeCookie);

        Assert.Null(forwarding.Authenticate(setupMessage));
    }

    [Fact]
    public void RejectsInvalidSetupMessage()
    {
        var forwarding = new X11Forwarding(NullLogger<SshClient>.Instance, default);
        X11Forwarding.Target target = forwarding.AddTarget(ParseDisplay(":0"), isTrusted: true, RandomNumberGenerator.GetBytes(16));
        byte[] setupMessage = CreateSetupMessage(bigEndian: false, XAuthority.MitMagicCookie, target.FakeCookie);

        byte[] invalidByteOrder = setupMessage.ToArray();
        invalidByteOrder[0] = (byte)'x';
        Assert.False(X11Forwarding.TryGetAuthenticationLengths(invalidByteOrder, out _, out _));
        Assert.Null(forwarding.Authenticate(invalidByteOrder));

        Assert.Null(forwarding.Authenticate(setupMessage.AsSpan(0, setupMessage.Length - 1)));
    }

    [Fact]
    public void RejectsExpiredTarget()
    {
        var forwarding = new X11Forwarding(NullLogger<SshClient>.Instance, default);
        X11Forwarding.Target target = forwarding.AddTarget(ParseDisplay(":0"), isTrusted: false, RandomNumberGenerator.GetBytes(16), refuseTimestamp: 1);

        Assert.True(target.IsExpired);
    }

    private static X11Display ParseDisplay(string name)
    {
        Assert.True(X11Display.TryParse(name, out X11Display? display));
        return display;
    }

    internal static byte[] CreateSetupMessage(bool bigEndian, string authenticationProtocol, byte[] authenticationData)
    {
        byte[] name = Encoding.ASCII.GetBytes(authenticationProtocol);
        byte[] message = new byte[X11Forwarding.GetSetupMessageLength(name.Length, authenticationData.Length)];
        message[0] = bigEndian ? (byte)'B' : (byte)'l';
        WriteUInt16(message.AsSpan(2), 11); // protocol-major-version
        WriteUInt16(message.AsSpan(4), 0);  // protocol-minor-version
        WriteUInt16(message.AsSpan(6), name.Length);
        WriteUInt16(message.AsSpan(8), authenticationData.Length);
        name.CopyTo(message, 12);
        authenticationData.CopyTo(message, 12 + Pad4(name.Length));
        return message;

        void WriteUInt16(Span<byte> destination, int value)
        {
            if (bigEndian)
            {
                BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)value);
            }
            else
            {
                BinaryPrimitives.WriteUInt16LittleEndian(destination, (ushort)value);
            }
        }
    }

    internal static byte[] GetAuthenticationData(byte[] setupMessage)
    {
        Assert.True(X11Forwarding.TryGetAuthenticationLengths(setupMessage, out int nameLength, out int dataLength));
        return setupMessage.AsSpan(12 + Pad4(nameLength), dataLength).ToArray();
    }

    private static int Pad4(int length)
        => (length + 3) & ~3;
}

[Collection(nameof(SshServerCollection))]
public class X11ForwardingTests
{
    private readonly SshServer _sshServer;

    public X11ForwardingTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task ForwardsConnectionToDisplay()
    {
        using var xServer = new FakeX11Server();
        byte[] cookie = RandomNumberGenerator.GetBytes(16);
        using TempFile xauthorityFile = new TempFile(Path.GetTempFileName());
        File.WriteAllBytes(xauthorityFile.Path, XAuthorityTests.Serialize(
            new XAuthority.Entry(XAuthority.FamilyInternet, [127, 0, 0, 1], xServer.DisplayNumber.ToString(CultureInfo.InvariantCulture), XAuthority.MitMagicCookie, cookie)));

        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.X11Display = $"127.0.0.1:{xServer.DisplayNumber}";
            settings.ForwardX11Trusted = true;
            settings.XAuthorityFilePath = xauthorityFile.Path;
        });

        using var process = await client.ExecuteAsync(CreateX11ClientCommand(useServerCookie: true), new ExecuteOptions() { ForwardX11 = true });
        Task<byte[]> acceptTask = xServer.AcceptAndReplyAsync("hello"u8.ToArray());
        (string stdout, string stderr) = await process.ReadToEndAsStringAsync();

        Assert.True(stdout == "hello", $"stdout: '{stdout}', stderr: '{stderr}'");
        byte[] setupMessage = await acceptTask.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(cookie, X11AuthenticationTests.GetAuthenticationData(setupMessage));
    }

    [Fact]
    public async Task RejectsConnectionWithInvalidCookie()
    {
        using var xServer = new FakeX11Server();

        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.X11Display = $"127.0.0.1:{xServer.DisplayNumber}";
            settings.ForwardX11Trusted = true;
            settings.XAuthorityFilePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        });

        using var process = await client.ExecuteAsync(CreateX11ClientCommand(useServerCookie: false), new ExecuteOptions() { ForwardX11 = true });
        (string stdout, string stderr) = await process.ReadToEndAsStringAsync();

        Assert.True(stdout == "", $"stdout: '{stdout}', stderr: '{stderr}'");
        Assert.False(xServer.HasPendingConnection);
    }

    [Theory]
    [InlineData(true, null, true)]
    [InlineData(true, false, false)]
    [InlineData(false, null, false)]
    [InlineData(false, true, true)]
    public async Task ForwardX11SettingAndOption(bool settingsForwardX11, bool? optionsForwardX11, bool expectDisplay)
    {
        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.ForwardX11 = settingsForwardX11;
            settings.X11Display = "localhost:0";
            settings.ForwardX11Trusted = true;
            settings.XAuthorityFilePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        });

        using var process = await client.ExecuteAsync("echo \"${DISPLAY:-none}\"", new ExecuteOptions() { ForwardX11 = optionsForwardX11 });
        // Only read stdout: the server's xauth may print a warning on stderr (e.g. when ~/.Xauthority doesn't exist yet).
        (_, string? line) = await process.ReadLineAsync(readStdout: true, readStderr: false);

        if (expectDisplay)
        {
            Assert.StartsWith("localhost:", line);
        }
        else
        {
            Assert.Equal("none", line);
        }
    }

    [Fact]
    public async Task SetupFailureFailsOperationWhenRequested()
    {
        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.ForwardX11 = true;
            settings.X11Display = "invalid";
        });

        await Assert.ThrowsAsync<SshOperationException>(() => client.ExecuteAsync("echo", new ExecuteOptions() { ForwardX11 = true }));

        // When enabled through the settings, the process starts without X11 forwarding.
        using var process = await client.ExecuteAsync("echo \"${DISPLAY:-none}\"");
        (_, string? line) = await process.ReadLineAsync();
        Assert.Equal("none", line);
    }

    [Fact]
    public async Task UntrustedRequiresXAuth()
    {
        using var client = await _sshServer.CreateClientAsync(settings =>
        {
            settings.X11Display = "localhost:0";
            settings.ForwardX11Trusted = false;
            settings.XAuthLocation = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName(), "xauth");
        });

        var exception = await Assert.ThrowsAsync<SshOperationException>(() => client.ExecuteAsync("echo", new ExecuteOptions() { ForwardX11 = true }));
        Assert.NotNull(exception.InnerException);
    }

    // Connects to the forwarded X11 display on the server and sends the X11 connection setup message.
    private static string CreateX11ClientCommand(bool useServerCookie)
    {
        string cookie = useServerCookie ? "$(xauth list \"unix:$d\" | awk '{print $3}' | head -n 1)" : "00000000000000000000000000000000";
        return
        $$"""
        [ -n "$DISPLAY" ] || { echo 'DISPLAY is not set' >&2; exit 1; }
        d=${DISPLAY#*:}; d=${d%.*}
        c={{cookie}}
        exec 3<>/dev/tcp/localhost/$((6000 + d)) || exit 1
        printf 'l\000\013\000\000\000\022\000\020\000\000\000MIT-MAGIC-COOKIE-1\000\000' >&3
        printf "$(echo $c | sed 's/../\\x&/g')" >&3
        head -c 5 <&3
        """;
    }

    private sealed class FakeX11Server : IDisposable
    {
        private const int BaseTcpPort = 6000;
        private const int SetupMessageLength = 48; // Setup message for a 16-byte MIT-MAGIC-COOKIE-1.

        private readonly Socket _listenSocket;

        public int DisplayNumber { get; }

        public FakeX11Server()
        {
            for (int displayNumber = 20; ; displayNumber++)
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(IPAddress.Loopback, BaseTcpPort + displayNumber));
                    socket.Listen();
                    _listenSocket = socket;
                    DisplayNumber = displayNumber;
                    return;
                }
                catch (SocketException) when (displayNumber < 100)
                {
                    socket.Dispose();
                }
            }
        }

        public bool HasPendingConnection => _listenSocket.Poll(0, SelectMode.SelectRead);

        public async Task<byte[]> AcceptAndReplyAsync(byte[] reply)
        {
            using Socket socket = await _listenSocket.AcceptAsync();
            using var stream = new NetworkStream(socket, ownsSocket: false);
            byte[] setupMessage = new byte[SetupMessageLength];
            await stream.ReadExactlyAsync(setupMessage);
            await stream.WriteAsync(reply);
            socket.Shutdown(SocketShutdown.Send);
            return setupMessage;
        }

        public void Dispose()
            => _listenSocket.Dispose();
    }
}
