// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using Org.BouncyCastle.Utilities.Zlib;

namespace Tmds.Ssh;

// Compresses payloads with zlib (RFC 1950) as described in https://tools.ietf.org/html/rfc4253#section-6.2.
// A single zlib stream spans all the payloads compressed by this instance. Each payload is deflated with a
// partial flush so the peer can inflate it immediately while the compression context is kept for the next payload.
sealed class ZLibCompressor : IDisposable
{
    // OpenSSH compresses using level 6.
    private const int CompressionLevel = 6;

    private ZStream? _zstream;

    public ZLibCompressor()
    {
        ZStream zstream = new ZStream();
        int status = zstream.deflateInit(CompressionLevel);
        if (status != JZlib.Z_OK)
        {
            ThrowHelper.ThrowInvalidOperation($"Failed to initialize compression: {status}.");
        }
        _zstream = zstream;
    }

    // Appends the compressed form of 'payload' to 'destination'.
    public void Compress(ReadOnlySequence<byte> payload, Sequence destination)
    {
        ZStream zstream = _zstream ?? throw new ObjectDisposedException(typeof(ZLibCompressor).FullName);

        int payloadLength = (int)payload.Length;
        byte[] input = ArrayPool<byte>.Shared.Rent(payloadLength);
        byte[] output = ArrayPool<byte>.Shared.Rent(Constants.PreferredBufferSize);
        try
        {
            payload.CopyTo(input);

            zstream.next_in = input;
            zstream.next_in_index = 0;
            zstream.avail_in = payloadLength;

            do
            {
                zstream.next_out = output;
                zstream.next_out_index = 0;
                zstream.avail_out = output.Length;

                int status = zstream.deflate(JZlib.Z_PARTIAL_FLUSH);
                if (status != JZlib.Z_OK)
                {
                    ThrowHelper.ThrowInvalidOperation($"Failed to compress packet: {zstream.msg ?? status.ToString()}.");
                }

                int produced = output.Length - zstream.avail_out;
                if (produced > 0)
                {
                    destination.Append(output.AsSpan(0, produced));
                }
                // When the output buffer was filled completely there may be more data.
            } while (zstream.avail_out == 0);

            // deflate consumes all the input before it returns with unused output space.
            Debug.Assert(zstream.avail_in == 0);
        }
        finally
        {
            // Don't hold on to the pooled arrays.
            zstream.next_in = null;
            zstream.next_out = null;

            ArrayPool<byte>.Shared.Return(output);
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    public void Dispose()
    {
        ZStream? zstream = _zstream;
        if (zstream is not null)
        {
            _zstream = null;
            zstream.deflateEnd();
            zstream.free();
        }
    }
}
