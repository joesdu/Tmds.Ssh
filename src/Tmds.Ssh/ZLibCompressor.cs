// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.IO.Compression;

namespace Tmds.Ssh;

// Compresses payloads with zlib (RFC 1950) as described in https://tools.ietf.org/html/rfc4253#section-6.2.
// A single zlib stream spans all the payloads compressed by this instance. Each payload is flushed so the
// peer can decompress it immediately while the compression context is kept for the next payload.
sealed class ZLibCompressor : IDisposable
{
    private readonly DestinationStream _destination;
    private readonly ZLibStream _deflater;

    public ZLibCompressor()
    {
        _destination = new DestinationStream();
        // CompressionLevel.Optimal is zlib level 6, which is the level used by OpenSSH.
        _deflater = new ZLibStream(_destination, CompressionLevel.Optimal, leaveOpen: true);
    }

    // Appends the compressed form of 'payload' to 'destination'.
    public void Compress(ReadOnlySequence<byte> payload, Sequence destination)
    {
        _destination.Sequence = destination;
        try
        {
            foreach (ReadOnlyMemory<byte> segment in payload)
            {
                _deflater.Write(segment.Span);
            }

            // Flush performs a sync flush which completes the data for this payload.
            _deflater.Flush();
        }
        finally
        {
            _destination.Sequence = null;
        }
    }

    public void Dispose()
    {
        // Disposing the deflater ends the zlib stream. That data is no longer meant for a peer.
        _deflater.Dispose();
        _destination.Dispose();
    }

    // Appends what is written to it to a Sequence. Writes are dropped when no Sequence is set.
    private sealed class DestinationStream : Stream
    {
        public Sequence? Sequence { get; set; }

        public override void Write(ReadOnlySpan<byte> buffer)
            => Sequence?.Append(buffer);

        public override void Write(byte[] buffer, int offset, int count)
            => Write(buffer.AsSpan(offset, count));

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
