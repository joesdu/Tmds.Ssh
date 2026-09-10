// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.IO.Compression;

namespace Tmds.Ssh;

// Decompresses payloads with zlib (RFC 1950) as described in https://tools.ietf.org/html/rfc4253#section-6.2.
// A single zlib stream spans all the payloads decompressed by this instance.
sealed class ZLibDecompressor : IDisposable
{
    // Matches how System.IO.Compression reads this switch. It is disabled by default.
    private static readonly bool s_useStrictValidation =
        AppContext.TryGetSwitch("System.IO.Compression.UseStrictValidation", out bool strictValidation) && strictValidation;

    private readonly SourceStream _source;
    private readonly ZLibStream _inflater;

    public ZLibDecompressor()
    {
        _source = new SourceStream();
        _inflater = new ZLibStream(_source, CompressionMode.Decompress, leaveOpen: true);
    }

    // Appends the decompressed form of 'payload' to 'destination'.
    // 'maxLength' bounds the decompressed length so a peer can not force us to allocate an arbitrary amount of memory.
    public void Decompress(ReadOnlySequence<byte> payload, Sequence destination, int maxLength)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.PreferredBufferSize);
        _source.Data = payload;
        try
        {
            long decompressedLength = 0;
            while (true)
            {
                int bytesRead;
                try
                {
                    bytesRead = _inflater.Read(buffer, 0, buffer.Length);
                }
                catch (InvalidDataException) when (s_useStrictValidation && decompressedLength > 0)
                {
                    // The peer flushed the zlib stream instead of ending it, so the read that finds no
                    // more data considers the stream truncated when strict validation is enabled.
                    // The decompressed data was returned by the preceding reads. Data that decompresses
                    // to nothing is not a payload we flushed through, so that is still treated as an error.
                    break;
                }
                catch (InvalidDataException e)
                {
                    ThrowHelper.ThrowProtocolCompressionError(e.Message, e);
                    throw;
                }

                if (bytesRead == 0)
                {
                    break;
                }

                decompressedLength += bytesRead;
                if (decompressedLength > maxLength)
                {
                    ThrowHelper.ThrowProtocolPacketTooLong();
                }

                destination.Append(buffer.AsSpan(0, bytesRead));
            }
        }
        finally
        {
            _source.Data = default;
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public void Dispose()
    {
        _inflater.Dispose();
        _source.Dispose();
    }

    // Reads from a Sequence. Returns zero when all of it was read.
    private sealed class SourceStream : Stream
    {
        public ReadOnlySequence<byte> Data { get; set; }

        public override int Read(Span<byte> buffer)
        {
            int length = (int)Math.Min(buffer.Length, Data.Length);
            if (length == 0)
            {
                return 0;
            }

            Data.Slice(0, length).CopyTo(buffer.Slice(0, length));
            Data = Data.Slice(length);

            return length;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsSpan(offset, count));

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
