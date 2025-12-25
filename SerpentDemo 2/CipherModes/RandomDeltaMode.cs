using SerpentDemo.Serpent;

namespace SerpentDemo.CipherModes;

public class RandomDeltaMode : ICipherMode
{
    public bool RequiresIV => true;
    
    private readonly Random _random = new();
    
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
        byte[] delta = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] newDelta = new byte[cipher.BlockSize];
            _random.NextBytes(newDelta);
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                newDelta[j] ^= delta[j];
            }
            
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                block[j] ^= newDelta[j];
            }
            
            byte[] encrypted = cipher.EncryptBlock(block, key, polynomial);
            Array.Copy(encrypted, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            
            delta = newDelta;
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
        
        var rng = new Random(BitConverter.ToInt32(iv, 0));
        
        int blockCount = data.Length / cipher.BlockSize;
        byte[] result = new byte[data.Length];
        byte[] delta = (byte[])iv.Clone();
        
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, i * cipher.BlockSize, block, 0, cipher.BlockSize);
            
            byte[] decrypted = cipher.DecryptBlock(block, key, polynomial);
            
            byte[] newDelta = new byte[cipher.BlockSize];
            rng.NextBytes(newDelta);
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                newDelta[j] ^= delta[j];
            }
            
            for (int j = 0; j < cipher.BlockSize; j++)
            {
                decrypted[j] ^= newDelta[j];
            }
            
            Array.Copy(decrypted, 0, result, i * cipher.BlockSize, cipher.BlockSize);
            delta = newDelta;
        }
        
        return result;
    }
}
