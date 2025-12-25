namespace EncryptionCoursework.Core;

public interface ICipherMode
{
    byte[] Encrypt(byte[] data, byte[] key, byte[]? iv, IBlockCipher cipher);
    byte[] Decrypt(byte[] data, byte[] key, byte[]? iv, IBlockCipher cipher);
    bool RequiresIV { get; }
}
