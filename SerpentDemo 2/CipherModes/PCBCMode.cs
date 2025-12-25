using SerpentDemo.Serpent;

namespace SerpentDemo.CipherModes;

public class PCBCMode : ICipherMode
{
    public bool RequiresIV => true;
    
    public byte[] Encrypt(byte[] data, byte[] key, byte[]? iv, ISerpentCipher cipher, IrreduciblePolynomial polynomial)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        if (iv == null || iv.Length != cipher.BlockSize) 
            throw new ArgumentException("IV must be provided and match block size");
        if (data.Length % cipher.BlockSize != 0) 
            throw new ArgumentException("Data length must be multiple of block size");
        
        int blockCount = data.Length / cipher.BlockSize;
        byte[] result = new byte[data.Length];
        byte[] previousPlaintext = (byte[])iv.Clone();
        byte[] previousCiphertext = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            // Сохраняем оригинальный блок для следующей итерации
            byte[] originalBlock = (byte[])block.Clone();
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                block[j] ^= (byte)(previousPlaintext[j] ^ previousCiphertext[j]);
            }
            
            byte[] encrypted = cipher.EncryptBlock(block, key, polynomial);
            Array.Copy(encrypted, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            
            previousPlaintext = originalBlock;
            previousCiphertext = encrypted;
        }
        
        return result;
    }
    
    public byte[] Decrypt(byte[] data, byte[] key, byte[]? iv, ISerpentCipher cipher, IrreduciblePolynomial polynomial)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        if (iv == null || iv.Length != cipher.BlockSize) 
            throw new ArgumentException("IV must be provided and match block size");
        if (data.Length % cipher.BlockSize != 0) 
            throw new ArgumentException("Data length must be multiple of block size");
        
        int blockCount = data.Length / cipher.BlockSize;
        byte[] result = new byte[data.Length];
        byte[] previousPlaintext = (byte[])iv.Clone();
        byte[] previousCiphertext = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            byte[] decrypted = cipher.DecryptBlock(block, key, polynomial);
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                decrypted[j] ^= (byte)(previousPlaintext[j] ^ previousCiphertext[j]);
            }
            
            Array.Copy(decrypted, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            
            previousPlaintext = decrypted;
            previousCiphertext = block;
        }
        
        return result;
    }
}
