using SerpentDemo.Enums;

namespace SerpentDemo.Serpent;

public interface ISerpentCipher
{
    int BlockSize { get; }
    int KeySize { get; }
    byte[] EncryptBlock(byte[] block, byte[] key, IrreduciblePolynomial polynomial);
    byte[] DecryptBlock(byte[] block, byte[] key, IrreduciblePolynomial polynomial);
    bool IsValidKeySize(byte[] key);
}
