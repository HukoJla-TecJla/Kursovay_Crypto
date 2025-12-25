namespace EncryptionCoursework.Core;
public interface IBlockCipher
{
    int BlockSize { get; }
    int KeySize { get; }
    
    byte[] EncryptBlock(byte[] block, byte[] key);
    byte[] DecryptBlock(byte[] block, byte[] key);
    bool IsValidKeySize(byte[] key);
}
