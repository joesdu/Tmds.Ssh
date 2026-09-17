// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

// Implements X11 forwarding for an SshSession.
// For each forwarded display, a fake authentication cookie is sent to the server.
// When the server opens an 'x11' channel, the fake cookie in the X11 connection setup message
// is replaced by the real cookie before the connection is forwarded to the local display.
sealed class X11Forwarding
{
    public const string AuthenticationProtocol = XAuthority.MitMagicCookie;

    private const int SetupHeaderLength = 12;
    private const int FakeCookieLength = 16;

    private static readonly byte[] AuthenticationProtocolBytes = Encoding.ASCII.GetBytes(AuthenticationProtocol);

    internal sealed class Target
    {
        public required X11Display Display { get; init; }
        public required bool IsTrusted { get; init; }
        public required byte[] Cookie { get; init; }
        public required byte[] FakeCookie { get; init; }
        public long RefuseTimestamp { get; init; } // 0: connections are never refused.

        public string FakeCookieHex => Convert.ToHexString(FakeCookie).ToLowerInvariant();

        public bool IsExpired => RefuseTimestamp != 0 && Stopwatch.GetTimestamp() >= RefuseTimestamp;
    }

    private readonly ILogger<SshClient> _logger;
    private readonly CancellationToken _connectionAborting;
    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _targetSemaphore = new(initialCount: 1); // Serializes GetTargetAsync.
    private readonly List<Target> _targets = new();

    public X11Forwarding(ILogger<SshClient> logger, CancellationToken connectionAborting)
    {
        _logger = logger;
        _connectionAborting = connectionAborting;
    }

    public bool HasTargets
    {
        get
        {
            lock (_gate)
            {
                return _targets.Count > 0;
            }
        }
    }

    public async Task<Target> GetTargetAsync(SshClientSettings settings, CancellationToken cancellationToken)
    {
        string? displayName = settings.X11Display;
        if (string.IsNullOrEmpty(displayName))
        {
            displayName = Environment.GetEnvironmentVariable("DISPLAY");
        }
        if (string.IsNullOrEmpty(displayName))
        {
            throw new SshOperationException("X11 forwarding requires a display: DISPLAY is not set.");
        }
        if (!X11Display.TryParse(displayName, out X11Display? display))
        {
            throw new SshOperationException($"X11 forwarding failed: can not parse display '{displayName}'.");
        }

        bool isTrusted = settings.ForwardX11Trusted;

        // Serialize so concurrent calls share a single target instead of each generating authentication data.
        await _targetSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                // Connections for expired targets are refused, so they no longer need to be kept.
                _targets.RemoveAll(target => target.IsExpired);

                foreach (var target in _targets)
                {
                    if (target.Display.Name == display.Name && target.IsTrusted == isTrusted && !target.IsExpired)
                    {
                        return target;
                    }
                }
            }

            byte[]? cookie;
            long refuseTimestamp = 0;
            if (isTrusted)
            {
                string xauthorityFilePath = settings.XAuthorityFilePath ?? XAuthority.GetDefaultFilePath();
                cookie = await XAuthority.FindCookieAsync(xauthorityFilePath, display, cancellationToken).ConfigureAwait(false);
                if (cookie is null)
                {
                    // Like OpenSSH, use random data. The X server may accept the connection when it doesn't require authentication.
                    _logger.X11NoAuthenticationData(display.Name, xauthorityFilePath);
                    cookie = RandomNumberGenerator.GetBytes(FakeCookieLength);
                }
            }
            else
            {
                TimeSpan timeout = settings.ForwardX11Timeout;
                try
                {
                    cookie = await XAuthority.GenerateUntrustedCookieAsync(settings.XAuthLocation, display, timeout, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    throw new SshOperationException($"Untrusted X11 forwarding setup failed: can not generate authentication data for display '{display.Name}' using '{settings.XAuthLocation}'.", ex);
                }
                if (timeout > TimeSpan.Zero)
                {
                    refuseTimestamp = Stopwatch.GetTimestamp() + (long)Math.Min(timeout.TotalSeconds * Stopwatch.Frequency, long.MaxValue / 2);
                }
            }

            return AddTarget(display, isTrusted, cookie, refuseTimestamp);
        }
        finally
        {
            _targetSemaphore.Release();
        }
    }

    internal Target AddTarget(X11Display display, bool isTrusted, byte[] cookie, long refuseTimestamp = 0)
    {
        var target = new Target()
        {
            Display = display,
            IsTrusted = isTrusted,
            Cookie = cookie,
            FakeCookie = RandomNumberGenerator.GetBytes(cookie.Length),
            RefuseTimestamp = refuseTimestamp
        };
        lock (_gate)
        {
            _targets.Add(target);
        }
        return target;
    }

    public void HandleConnection(SshDataStream channelStream, string originatorAddress, uint originatorPort)
        => _ = ForwardConnectionAsync(channelStream, $"{originatorAddress}:{originatorPort}");

    private async Task ForwardConnectionAsync(SshDataStream channelStream, string sourceAddress)
    {
        // Don't block the SshSession receive loop.
        await Task.Yield();

        Stream? displayStream = null;
        string? displayName = null;
        try
        {
            byte[] header = new byte[SetupHeaderLength];
            await channelStream.ReadExactlyAsync(header, _connectionAborting).ConfigureAwait(false);
            if (!TryGetAuthenticationLengths(header, out int nameLength, out int dataLength))
            {
                _logger.X11ConnectionRejected(sourceAddress, "invalid connection setup message");
                return;
            }
            byte[] setupMessage = new byte[GetSetupMessageLength(nameLength, dataLength)];
            header.CopyTo(setupMessage, 0);
            await channelStream.ReadExactlyAsync(setupMessage.AsMemory(SetupHeaderLength), _connectionAborting).ConfigureAwait(false);

            Target? target = Authenticate(setupMessage);
            if (target is null)
            {
                _logger.X11ConnectionRejected(sourceAddress, "authentication data does not match");
                return;
            }
            if (target.IsExpired)
            {
                _logger.X11ConnectionRejected(sourceAddress, "ForwardX11Timeout expired");
                return;
            }

            displayName = target.Display.Name;
            _logger.X11ConnectionForward(sourceAddress, displayName);
            displayStream = await target.Display.ConnectAsync(_connectionAborting).ConfigureAwait(false);
            await displayStream.WriteAsync(setupMessage, _connectionAborting).ConfigureAwait(false);

            await SshSession.ForwardStreamsAsync(channelStream, displayStream).ConfigureAwait(false);

            _logger.X11ConnectionClosed(sourceAddress, displayName);
        }
        catch (EndOfStreamException) when (displayName is null)
        {
            // The X11 client closed the connection before completing the connection setup.
            _logger.X11ConnectionRejected(sourceAddress, "connection closed during connection setup");
        }
        catch (Exception ex)
        {
            // Don't log when the connection is aborting.
            if (!_connectionAborting.IsCancellationRequested)
            {
                _logger.X11ConnectionAborted(sourceAddress, displayName, ex);
            }
        }
        finally
        {
            channelStream.Dispose();
            displayStream?.Dispose();
        }
    }

    // Finds the target for the fake authentication data of the setup message and replaces it with the real data.
    internal Target? Authenticate(Span<byte> setupMessage)
    {
        if (!TryGetAuthenticationLengths(setupMessage, out int nameLength, out int dataLength) ||
            setupMessage.Length != GetSetupMessageLength(nameLength, dataLength))
        {
            return null;
        }

        Span<byte> name = setupMessage.Slice(SetupHeaderLength, nameLength);
        Span<byte> data = setupMessage.Slice(SetupHeaderLength + Pad4(nameLength), dataLength);
        if (!name.SequenceEqual(AuthenticationProtocolBytes))
        {
            return null;
        }

        lock (_gate)
        {
            foreach (var target in _targets)
            {
                if (CryptographicOperations.FixedTimeEquals(data, target.FakeCookie))
                {
                    target.Cookie.CopyTo(data);
                    return target;
                }
            }
        }

        return null;
    }

    internal static bool TryGetAuthenticationLengths(ReadOnlySpan<byte> setupMessage, out int nameLength, out int dataLength)
    {
        /*
            X11 connection setup:
            CARD8     byte-order: 'B' (MSB first) or 'l' (LSB first)
            BYTE      unused
            CARD16    protocol-major-version
            CARD16    protocol-minor-version
            CARD16    n, length of authorization-protocol-name
            CARD16    d, length of authorization-protocol-data
            CARD16    unused
            STRING8   authorization-protocol-name
            p         unused, p=pad(n)
            STRING8   authorization-protocol-data
            q         unused, q=pad(d)
        */
        nameLength = 0;
        dataLength = 0;
        if (setupMessage.Length < SetupHeaderLength)
        {
            return false;
        }
        switch (setupMessage[0])
        {
            case (byte)'B':
                nameLength = BinaryPrimitives.ReadUInt16BigEndian(setupMessage.Slice(6));
                dataLength = BinaryPrimitives.ReadUInt16BigEndian(setupMessage.Slice(8));
                return true;
            case (byte)'l':
                nameLength = BinaryPrimitives.ReadUInt16LittleEndian(setupMessage.Slice(6));
                dataLength = BinaryPrimitives.ReadUInt16LittleEndian(setupMessage.Slice(8));
                return true;
            default:
                return false;
        }
    }

    internal static int GetSetupMessageLength(int nameLength, int dataLength)
        => SetupHeaderLength + Pad4(nameLength) + Pad4(dataLength);

    private static int Pad4(int length)
        => (length + 3) & ~3;
}
