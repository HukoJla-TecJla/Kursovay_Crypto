using EncryptionCoursework.Core;

namespace EncryptionCoursework.Algorithms;

/// <summary>
/// Реализация алгоритма TripleDES (3DES)
/// </summary>
public class TripleDES : IBlockCipher
{
    public int BlockSize => 8; // 64 бита
    public int KeySize => 24; // 192 бита (три ключа по 64 бита)
    
    private readonly DES _des = new();
    
    public byte[] EncryptBlock(byte[] block, byte[] key)
    {
        if (block == null || block.Length != BlockSize)
            throw new ArgumentException($"Block must be {BlockSize} bytes");
        if (!IsValidKeySize(key))
            throw new ArgumentException($"Key must be {KeySize} bytes");
        
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        byte[] key3 = new byte[8];
        
        Array.Copy(key, 0, key1, 0, 8);
        Array.Copy(key, 8, key2, 0, 8);
        Array.Copy(key, 16, key3, 0, 8);
        
        byte[] result = _des.EncryptBlock(block, key1);
        result = _des.DecryptBlock(result, key2);
        result = _des.EncryptBlock(result, key3);
        
        return result;
    }
    
    public byte[] DecryptBlock(byte[] block, byte[] key)
    {
        if (block == null || block.Length != BlockSize)
            throw new ArgumentException($"Block must be {BlockSize} bytes");
        if (!IsValidKeySize(key))
            throw new ArgumentException($"Key must be {KeySize} bytes");
        
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        byte[] key3 = new byte[8];
        
        Array.Copy(key, 0, key1, 0, 8);
        Array.Copy(key, 8, key2, 0, 8);
        Array.Copy(key, 16, key3, 0, 8);
        
    
        byte[] result = _des.DecryptBlock(block, key3);
        result = _des.EncryptBlock(result, key2);
        result = _des.DecryptBlock(result, key1);
        
        return result;
    }
    
    public bool IsValidKeySize(byte[] key)
    {
        return key != null && key.Length == KeySize;
    }
}
