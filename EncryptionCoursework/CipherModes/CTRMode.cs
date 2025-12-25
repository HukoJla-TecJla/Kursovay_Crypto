using EncryptionCoursework.Core;

namespace EncryptionCoursework.CipherModes;


public class CTRMode : ICipherMode
{
    public bool RequiresIV => true;
    
    private static void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }
    
    public byte[] Encrypt(byte[] data, byte[] key, byte[]? iv, IBlockCipher cipher)
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
        byte[] counter = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
           
            byte[] encryptedCounter = cipher.EncryptBlock(counter, key);
            
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                block[j] ^= encryptedCounter[j];
            }
            
            Array.Copy(block, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            IncrementCounter(counter);
        }
        
        return result;
    }
    
    public byte[] Decrypt(byte[] data, byte[] key, byte[]? iv, IBlockCipher cipher)
    {
      
        return Encrypt(data, key, iv, cipher);
    }
}
