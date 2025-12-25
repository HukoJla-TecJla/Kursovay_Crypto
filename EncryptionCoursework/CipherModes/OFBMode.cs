using EncryptionCoursework.Core;

namespace EncryptionCoursework.CipherModes;


public class OFBMode : ICipherMode
{
    public bool RequiresIV => true;
    
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
        byte[] feedback = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
           
            feedback = cipher.EncryptBlock(feedback, key);
            
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
           
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                block[j] ^= feedback[j];
            }
            
            Array.Copy(block, 0, result, i * cipher.BlockSize, cipher.BlockSize);
        }
        
        return result;
    }
    
    public byte[] Decrypt(byte[] data, byte[] key, byte[]? iv, IBlockCipher cipher)
    {
    
        return Encrypt(data, key, iv, cipher);
    }
}
