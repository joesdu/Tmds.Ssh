// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// Compresses the payload of outgoing packets before they are encrypted by the wrapped encryptor.
sealed class ZLibPacketEncryptor : IPacketEncryptor
{
    private readonly IPacketEncryptor _encryptor;
    private readonly SequencePool _sequencePool;
    private ZLibCompressor? _compressor;
    private bool _startCompressionAfterAuthentication;

    public ZLibPacketEncryptor(IPacketEncryptor encryptor, SequencePool sequencePool, bool delayCompression)
    {
        _encryptor = encryptor;
        _sequencePool = sequencePool;
        if (delayCompression)
        {
            _startCompressionAfterAuthentication = true;
        }
        else
        {
            _compressor = new ZLibCompressor();
        }
    }

    public void Encrypt(uint sequenceNumber, Packet packet, Sequence buffer)
    {
        ZLibCompressor? compressor = _compressor;
        if (compressor is null)
        {
            _encryptor.Encrypt(sequenceNumber, packet, buffer);
            return;
        }

        using Packet uncompressed = packet.Move(); // Dispose the packet.

        Sequence sequence = _sequencePool.RentSequence();
        Packet compressed = new Packet(sequence); // Reserves the packet header.
        try
        {
            compressor.Compress(uncompressed.Payload, sequence);
        }
        catch
        {
            compressed.Dispose();
            throw;
        }

        _encryptor.Encrypt(sequenceNumber, compressed.Move(), buffer);
    }

    public void EnableDelayedCompression()
    {
        if (_startCompressionAfterAuthentication)
        {
            _startCompressionAfterAuthentication = false;
            _compressor = new ZLibCompressor();
        }
    }

    public void Dispose()
    {
        _compressor?.Dispose();
        _encryptor.Dispose();
    }
}
