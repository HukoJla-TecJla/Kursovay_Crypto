using SerpentDemo.Serpent;

namespace SerpentDemo.CipherModes;

public interface ICipherMode
{
    byte[] Encrypt(byte[] data, byte[] key, byte[]? iv, ISerpentCipher cipher, IrreduciblePolynomial polynomial);
    byte[] Decrypt(byte[] data, byte[] key, byte[]? iv, ISerpentCipher cipher, IrreduciblePolynomial polynomial);
    bool RequiresIV { get; }
}
