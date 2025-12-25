using SerpentDemo.Serpent;

namespace SerpentDemo.CipherModes;

public class ECBMode : ICipherMode
{
    public bool RequiresIV => false;
    
    public byte[] Encrypt(byte[] data, byte[] key, byte[]? iv, ISerpentCipher cipher, IrreduciblePolynomial polynomial)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        if (data.Length % cipher.BlockSize != 0) 
            throw new ArgumentException("Data length must be multiple of block size");
        
        int blockCount = data.Length / cipher.BlockSize;
        byte[] result = new byte[data.Length];
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            byte[] encrypted = cipher.EncryptBlock(block, key, polynomial);
            Array.Copy(encrypted, 0, result, i * cipher.BlockSize, cipher.BlockSize);
        }
        
        return result;
    }
    
    public byte[] Decrypt(byte[] data, byte[] key, byte[]? iv, ISerpentCipher cipher, IrreduciblePolynomial polynomial)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        if (data.Length % cipher.BlockSize != 0) 
            throw new ArgumentException("Data length must be multiple of block size");
        
        int blockCount = data.Length / cipher.BlockSize;
        byte[] result = new byte[data.Length];
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            byte[] decrypted = cipher.DecryptBlock(block, key, polynomial);
            Array.Copy(decrypted, 0, result, i * cipher.BlockSize, cipher.BlockSize);
        }
        
        return result;
    }
}
