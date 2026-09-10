// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class PacketCompressionAlgorithm
{
    // 'zlib@openssh.com' only starts compressing after the user has authenticated.
    private readonly bool _delayCompression;

    private PacketCompressionAlgorithm(bool delayCompression)
    {
        _delayCompression = delayCompression;
    }

    public IPacketEncryptor CreatePacketEncryptor(IPacketEncryptor encryptor, SequencePool sequencePool, bool isAuthenticated)
        => new ZLibPacketEncryptor(encryptor, sequencePool, delayCompression: _delayCompression && !isAuthenticated);

    public IPacketDecryptor CreatePacketDecryptor(IPacketDecryptor decryptor, SequencePool sequencePool, bool isAuthenticated)
        => new ZLibPacketDecryptor(decryptor, sequencePool, delayCompression: _delayCompression && !isAuthenticated);

    // Returns null when the packets are not compressed.
    public static PacketCompressionAlgorithm? Find(Name name)
    {
        if (name == AlgorithmNames.None)
        {
            return null;
        }
        else if (name == AlgorithmNames.ZLib)
        {
            return new PacketCompressionAlgorithm(delayCompression: false);
        }
        else if (name == AlgorithmNames.ZLibOpenSsh)
        {
            return new PacketCompressionAlgorithm(delayCompression: true);
        }

        throw new NotSupportedException($"Compression algorithm '{name}' is not supported.");
    }
}
