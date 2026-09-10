// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// Decompresses the payload of incoming packets after they were decrypted by the wrapped decryptor.
sealed class ZLibPacketDecryptor : IPacketDecryptor
{
    private readonly IPacketDecryptor _decryptor;
    private readonly SequencePool _sequencePool;
    private ZLibDecompressor? _decompressor;
    private bool _startCompressionAfterAuthentication;

    public ZLibPacketDecryptor(IPacketDecryptor decryptor, SequencePool sequencePool, bool delayCompression)
    {
        _decryptor = decryptor;
        _sequencePool = sequencePool;
        if (delayCompression)
        {
            _startCompressionAfterAuthentication = true;
        }
        else
        {
            _decompressor = new ZLibDecompressor();
        }
    }

    public bool TryDecrypt(Sequence receiveBuffer, uint sequenceNumber, int maxLength, out Packet packet)
    {
        if (!_decryptor.TryDecrypt(receiveBuffer, sequenceNumber, maxLength, out packet))
        {
            return false;
        }

        ZLibDecompressor? decompressor = _decompressor;
        if (decompressor is null)
        {
            return true;
        }

        using Packet compressed = packet.Move(); // Dispose the packet.

        Sequence sequence = _sequencePool.RentSequence();
        Packet decompressed = new Packet(sequence); // Reserves the packet header.
        try
        {
            decompressor.Decompress(compressed.Payload, sequence, maxLength);

            if (decompressed.PayloadLength == 0)
            {
                ThrowHelper.ThrowProtocolInvalidPacketLength();
            }
        }
        catch
        {
            decompressed.Dispose();
            throw;
        }

        packet = decompressed.Move();
        return true;
    }

    public void EnableDelayedCompression()
    {
        if (_startCompressionAfterAuthentication)
        {
            _startCompressionAfterAuthentication = false;
            _decompressor = new ZLibDecompressor();
        }
    }

    public void Dispose()
    {
        _decompressor?.Dispose();
        _decryptor.Dispose();
    }
}
