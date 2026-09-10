// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using Org.BouncyCastle.Utilities.Zlib;

namespace Tmds.Ssh;

// Decompresses payloads with zlib (RFC 1950) as described in https://tools.ietf.org/html/rfc4253#section-6.2.
// A single zlib stream spans all the payloads decompressed by this instance.
sealed class ZLibDecompressor : IDisposable
{
    private ZStream? _zstream;

    public ZLibDecompressor()
    {
        ZStream zstream = new ZStream();
        int status = zstream.inflateInit();
        if (status != JZlib.Z_OK)
        {
            ThrowHelper.ThrowInvalidOperation($"Failed to initialize decompression: {status}.");
        }
        _zstream = zstream;
    }

    // Appends the decompressed form of 'payload' to 'destination'.
    // 'maxLength' bounds the decompressed length so a peer can not force us to allocate an arbitrary amount of memory.
    public void Decompress(ReadOnlySequence<byte> payload, Sequence destination, int maxLength)
    {
        ZStream zstream = _zstream ?? throw new ObjectDisposedException(typeof(ZLibDecompressor).FullName);

        int payloadLength = (int)payload.Length;
        byte[] input = ArrayPool<byte>.Shared.Rent(payloadLength);
        byte[] output = ArrayPool<byte>.Shared.Rent(Constants.PreferredBufferSize);
        try
        {
            payload.CopyTo(input);

            zstream.next_in = input;
            zstream.next_in_index = 0;
            zstream.avail_in = payloadLength;

            long decompressedLength = 0;
            do
            {
                zstream.next_out = output;
                zstream.next_out_index = 0;
                zstream.avail_out = output.Length;

                int status = zstream.inflate(JZlib.Z_PARTIAL_FLUSH);

                int produced = output.Length - zstream.avail_out;
                if (produced > 0)
                {
                    decompressedLength += produced;
                    if (decompressedLength > maxLength)
                    {
                        ThrowHelper.ThrowProtocolPacketTooLong();
                    }

                    destination.Append(output.AsSpan(0, produced));
                }

                // zlib returns Z_BUF_ERROR when it can no longer make progress, that is: when all
                // the input was consumed and all the decompressed data was returned.
                if (status == JZlib.Z_BUF_ERROR)
                {
                    break;
                }
                if (status != JZlib.Z_OK)
                {
                    ThrowHelper.ThrowProtocolCompressionError(zstream.msg ?? status.ToString());
                }
                // When the output buffer was filled completely there may be more data.
            } while (zstream.avail_out == 0);

            // All the input is consumed when the peer compressed the payload with a partial flush.
            if (zstream.avail_in != 0)
            {
                ThrowHelper.ThrowProtocolCompressionError("the payload was not fully decompressed");
            }
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
            zstream.inflateEnd();
            zstream.free();
        }
    }
}
