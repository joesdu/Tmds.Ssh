// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Tmds.Ssh;

// Reads X11 authorization data from Xauthority files, and generates untrusted authorization data using xauth.
static class XAuthority
{
    public const string MitMagicCookie = "MIT-MAGIC-COOKIE-1";

    // Address families from Xauth.h.
    internal const ushort FamilyInternet = 0;
    internal const ushort FamilyInternet6 = 6;
    internal const ushort FamilyLocal = 256;
    internal const ushort FamilyWild = 65535;

    // Like OpenSSH, the xauth timeout is extended so the cookie outlives ForwardX11Timeout.
    private const int UntrustedTimeoutSlackSeconds = 60;

    private static readonly TimeSpan XAuthTimeout = TimeSpan.FromSeconds(30);

    internal readonly record struct Entry(ushort Family, byte[] Address, string Number, string Name, byte[] Data);

    public static string GetDefaultFilePath()
    {
        string? path = Environment.GetEnvironmentVariable("XAUTHORITY");
        return string.IsNullOrEmpty(path) ? Path.Combine(SshClientSettings.Home, ".Xauthority") : path;
    }

    // Returns the MIT-MAGIC-COOKIE-1 data for the display, or 'null' when there is none.
    public static async Task<byte[]?> FindCookieAsync(string filePath, X11Display display, CancellationToken cancellationToken)
    {
        byte[] content;
        try
        {
            content = await File.ReadAllBytesAsync(filePath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        List<(ushort Family, byte[] Address)> addresses = await GetAddressesAsync(display, cancellationToken).ConfigureAwait(false);
        return FindCookie(ParseEntries(content), display.DisplayNumber, addresses);
    }

    internal static byte[]? FindCookie(IEnumerable<Entry> entries, int displayNumber, List<(ushort Family, byte[] Address)> addresses)
    {
        string number = displayNumber.ToString(CultureInfo.InvariantCulture);
        foreach (var entry in entries)
        {
            if (entry.Name != MitMagicCookie || entry.Number != number || entry.Data.Length == 0)
            {
                continue;
            }
            if (entry.Family == FamilyWild)
            {
                return entry.Data;
            }
            foreach (var (family, address) in addresses)
            {
                if (entry.Family == family && entry.Address.AsSpan().SequenceEqual(address))
                {
                    return entry.Data;
                }
            }
        }
        return null;
    }

    internal static List<Entry> ParseEntries(ReadOnlySpan<byte> content)
    {
        /*
            Each entry is (integers are big-endian):
            uint16    family
            uint16    address length, followed by the address
            uint16    display number length, followed by the display number
            uint16    name length, followed by the name
            uint16    data length, followed by the data
        */
        List<Entry> entries = new();
        while (TryReadUInt16(ref content, out ushort family) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> address) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> number) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> name) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> data))
        {
            entries.Add(new Entry(family, address.ToArray(), Encoding.ASCII.GetString(number), Encoding.ASCII.GetString(name), data.ToArray()));
        }
        return entries;

        static bool TryReadUInt16(ref ReadOnlySpan<byte> content, out ushort value)
        {
            if (content.Length < 2)
            {
                value = 0;
                return false;
            }
            value = BinaryPrimitives.ReadUInt16BigEndian(content);
            content = content.Slice(2);
            return true;
        }

        static bool TryReadBytes(ref ReadOnlySpan<byte> content, out ReadOnlySpan<byte> value)
        {
            if (!TryReadUInt16(ref content, out ushort length) || content.Length < length)
            {
                value = default;
                return false;
            }
            value = content.Slice(0, length);
            content = content.Slice(length);
            return true;
        }
    }

    private static async Task<List<(ushort Family, byte[] Address)>> GetAddressesAsync(X11Display display, CancellationToken cancellationToken)
    {
        List<(ushort, byte[])> addresses = new();

        string localHostName = Dns.GetHostName();
        string? host = display.Host;
        IPAddress[] hostAddresses = [];
        if (host is not null)
        {
            if (IPAddress.TryParse(host, out IPAddress? ipAddress))
            {
                hostAddresses = [ipAddress];
            }
            else
            {
                try
                {
                    hostAddresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException)
                { }
            }
        }

        // Like Xlib, connections to the local host are authorized using the local hostname.
        if (host is null ||
            hostAddresses.Any(IPAddress.IsLoopback) ||
            string.Equals(host, localHostName, StringComparison.OrdinalIgnoreCase))
        {
            addresses.Add((FamilyLocal, Encoding.ASCII.GetBytes(localHostName)));
        }
        foreach (var hostAddress in hostAddresses)
        {
            IPAddress address = hostAddress.IsIPv4MappedToIPv6 ? hostAddress.MapToIPv4() : hostAddress;
            ushort family = address.AddressFamily == AddressFamily.InterNetwork ? FamilyInternet : FamilyInternet6;
            addresses.Add((family, address.GetAddressBytes()));
        }

        return addresses;
    }

    public static async Task<byte[]> GenerateUntrustedCookieAsync(string xauthLocation, X11Display display, TimeSpan timeout, CancellationToken cancellationToken)
    {
        DirectoryInfo directory = Directory.CreateTempSubdirectory("tmds-ssh-xauth-");
        try
        {
            string filePath = Path.Combine(directory.FullName, "xauthfile");
            var psi = new ProcessStartInfo()
            {
                FileName = xauthLocation,
                ArgumentList = { "-q", "-f", filePath, "generate", display.XAuthDisplayName, MitMagicCookie, "untrusted" },
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            if (timeout > TimeSpan.Zero)
            {
                double seconds = Math.Min(uint.MaxValue, Math.Ceiling(timeout.TotalSeconds) + UntrustedTimeoutSlackSeconds);
                psi.ArgumentList.Add("timeout");
                psi.ArgumentList.Add(((uint)seconds).ToString(CultureInfo.InvariantCulture));
            }

            using Process process = Process.Start(psi)!;
            process.StandardInput.Close();
            // xauth connects to the X server, don't wait indefinitely when it is unreachable.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(XAuthTimeout);
            Task<string> readStdout = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            Task<string> readStderr = process.StandardError.ReadToEndAsync(timeoutCts.Token);
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill();
                }
                catch
                { }

                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException($"'{xauthLocation}' did not complete within {XAuthTimeout.TotalSeconds} seconds.");
            }
            await readStdout.ConfigureAwait(false);
            string stderr = await readStderr.ConfigureAwait(false);

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"'{xauthLocation}' exited with code {process.ExitCode}: {stderr.Trim()}");
            }

            if (File.Exists(filePath))
            {
                foreach (var entry in ParseEntries(await File.ReadAllBytesAsync(filePath, cancellationToken).ConfigureAwait(false)))
                {
                    if (entry.Name == MitMagicCookie && entry.Data.Length > 0)
                    {
                        return entry.Data;
                    }
                }
            }

            throw new InvalidOperationException($"'{xauthLocation}' did not generate authentication data.");
        }
        finally
        {
            try
            {
                directory.Delete(recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { }
        }
    }
}
