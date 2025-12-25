using SerpentDemo.Serpent;

namespace SerpentDemo.CipherModes;

public class CFBMode : ICipherMode
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
        byte[] feedback = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] encryptedFeedback = cipher.EncryptBlock(feedback, key, polynomial);
            
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                encryptedFeedback[j] ^= block[j];
            }
            
            Array.Copy(encryptedFeedback, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            feedback = encryptedFeedback;
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
        byte[] feedback = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            byte[] encryptedFeedback = cipher.EncryptBlock(feedback, key, polynomial);
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                encryptedFeedback[j] ^= block[j];
            }
            
            Array.Copy(encryptedFeedback, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            feedback = block;
        }
        
        return result;
    }
}
