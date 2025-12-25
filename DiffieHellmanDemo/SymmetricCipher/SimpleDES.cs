using System.Numerics;

namespace DiffieHellmanDemo.SymmetricCipher;

public class SimpleDES
{
    private const int BlockSize = 8; // 64 бита
    
    
    public static byte[] DeriveKey(BigInteger sharedSecret, int keySize)
    {
        byte[] secretBytes = sharedSecret.ToByteArray(isUnsigned: true, isBigEndian: true);
    
        byte[] key = new byte[keySize];
        
       
        if (secretBytes.Length >= keySize)
        {
            Array.Copy(secretBytes, 0, key, 0, keySize);
        }
        else
        {
            int offset = 0;
            while (offset < keySize)
            {
                int toCopy = Math.Min(secretBytes.Length, keySize - offset);
                Array.Copy(secretBytes, 0, key, offset, toCopy);
                offset += toCopy;
            }
        }
        
        return key;
    }
    
    public static byte[] Encrypt(byte[] data, byte[] key)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (key == null || key.Length == 0) throw new ArgumentNullException(nameof(key));
        
        byte[] result = new byte[data.Length];
        
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        
        return result;
    }
    
    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        return Encrypt(data, key); 
    }
}
