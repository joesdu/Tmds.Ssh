// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class PacketCompressionAlgorithm
{
    private PacketCompressionAlgorithm()
    { }

    // 'zlib@openssh.com' only starts compressing after the user has authenticated.
    public IPacketEncryptor CreatePacketEncryptor(IPacketEncryptor encryptor, SequencePool sequencePool, bool isAuthenticated)
        => new ZLibPacketEncryptor(encryptor, sequencePool, delayCompression: !isAuthenticated);

    public IPacketDecryptor CreatePacketDecryptor(IPacketDecryptor decryptor, SequencePool sequencePool, bool isAuthenticated)
        => new ZLibPacketDecryptor(decryptor, sequencePool, delayCompression: !isAuthenticated);

    // Returns null when the packets are not compressed.
    public static PacketCompressionAlgorithm? Find(Name name)
    {
        if (name == AlgorithmNames.None)
        {
            return null;
        }
        else if (name == AlgorithmNames.ZLibOpenSsh)
        {
            return new PacketCompressionAlgorithm();
        }

        throw new NotSupportedException($"Compression algorithm '{name}' is not supported.");
    }
}
