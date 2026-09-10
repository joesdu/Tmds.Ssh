using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class CompressionTests
{
    // OpenSSH server only offers 'zlib@openssh.com'.
    private const string ServerCompressionAlgorithm = "zlib@openssh.com";

    private readonly SshServer _sshServer;

    public CompressionTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task ConnectWithCompressionClientToServer()
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.CompressionAlgorithmsClientToServer = [ ServerCompressionAlgorithm, "none" ]
        );
    }

    [Fact]
    public async Task ConnectWithCompressionServerToClient()
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings => settings.CompressionAlgorithmsServerToClient = [ ServerCompressionAlgorithm, "none" ]
        );
    }

    [Fact]
    public async Task ConnectWithCompressionSkipsUnknown()
    {
        using var _ = await _sshServer.CreateClientAsync(
            settings =>
            {
                settings.CompressionAlgorithmsClientToServer = [ "dummy-algorithm", ServerCompressionAlgorithm, "none" ];
                settings.CompressionAlgorithmsServerToClient = [ "dummy-algorithm", ServerCompressionAlgorithm, "none" ];
            }
        );
    }

    [Fact]
    public async Task ConnectFailsWhenNoCommonCompressionAlgorithm()
    {
        await Assert.ThrowsAnyAsync<SshConnectionException>(() =>
            _sshServer.CreateClientAsync(
                settings => settings.CompressionAlgorithmsClientToServer = [ "dummy-algorithm" ]
            ));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DataRoundTrips(bool compressible)
    {
        using var client = await CreateCompressingClientAsync();

        using var process = await client.ExecuteAsync("cat");

        // Include sizes that span multiple channel packets.
        foreach (int length in new[] { 1, 100, 4096, 40_000, 100_000 })
        {
            byte[] sendBuffer = new byte[length];
            if (compressible)
            {
                for (int i = 0; i < sendBuffer.Length; i++)
                {
                    sendBuffer[i] = (byte)('a' + (i % 26));
                }
            }
            else
            {
                Random.Shared.NextBytes(sendBuffer);
            }

            var writeTask = process.WriteAsync(sendBuffer).AsTask();

            byte[] receiveBuffer = new byte[length];
            int receiveBufferOffset = 0;
            do
            {
                Memory<byte> dst = receiveBuffer.AsMemory(receiveBufferOffset);
                (bool isError, int bytesRead) = await process.ReadAsync(dst, dst);
                Assert.False(isError);
                Assert.NotEqual(0, bytesRead);
                receiveBufferOffset += bytesRead;
            } while (receiveBufferOffset != receiveBuffer.Length);

            await writeTask;

            Assert.Equal(sendBuffer, receiveBuffer);
        }
    }

    [Fact]
    public async Task CompressionStartsAfterAuthentication()
    {
        // 'zlib@openssh.com' only starts compressing after the user has authenticated.
        // Verify the messages that are exchanged before and after that point.
        using var client = await CreateCompressingClientAsync();

        using var process = await client.ExecuteAsync("echo hello");

        (string stdout, string stderr) = await process.ReadToEndAsStringAsync();

        Assert.Equal("hello\n", stdout);
        Assert.Equal("", stderr);
        Assert.Equal(0, await process.GetExitCodeAsync());
    }

    [Fact]
    public async Task ConnectWithCompressionEnabledThroughSshConfig()
    {
        var options = new SshConfigSettings()
        {
            ConfigFilePaths = [],
            Options = new Dictionary<SshConfigOption, SshConfigOptionValue>()
            {
                { SshConfigOption.Hostname, "localhost" },
                { SshConfigOption.User, _sshServer.TestUser },
                { SshConfigOption.Port, _sshServer.ServerPort.ToString() },
                { SshConfigOption.IdentityFile, _sshServer.TestUserIdentityFile },
                { SshConfigOption.StrictHostKeyChecking, "no" },
                { SshConfigOption.UserKnownHostsFile, Path.Combine(Path.GetTempPath(), Path.GetTempFileName()) },
                { SshConfigOption.Compression, "yes" },
            }
        };

        using var client = new SshClient("dummy", options);
        await client.ConnectAsync();

        using var process = await client.ExecuteAsync("echo hello");
        (string stdout, _) = await process.ReadToEndAsStringAsync();
        Assert.Equal("hello\n", stdout);
    }

    private Task<SshClient> CreateCompressingClientAsync()
        => _sshServer.CreateClientAsync(
            settings =>
            {
                settings.CompressionAlgorithmsClientToServer = [ ServerCompressionAlgorithm, "none" ];
                settings.CompressionAlgorithmsServerToClient = [ ServerCompressionAlgorithm, "none" ];
            }
        );
}
