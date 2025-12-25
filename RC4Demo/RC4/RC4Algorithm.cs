namespace RC4Demo.RC4;


public class RC4Algorithm
{

    private static byte[] InitializeSBox(byte[] key)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        
        byte[] S = new byte[256];
        
       
        for (int i = 0; i < 256; i++)
        {
            S[i] = (byte)i;
        }
        
        
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) % 256;
            
           
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }
        
        return S;
    }
    private static byte GenerateKeyStreamByte(byte[] S, ref int i, ref int j)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        
     
        byte temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        
      
        int K = S[(S[i] + S[j]) % 256];
        return (byte)K;
    }
    
    public byte[] Process(byte[] data, byte[] key)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        
        byte[] S = InitializeSBox(key);
        byte[] result = new byte[data.Length];
        int i = 0, j = 0;
        
        for (int k = 0; k < data.Length; k++)
        {
            byte keyStreamByte = GenerateKeyStreamByte(S, ref i, ref j);
            result[k] = (byte)(data[k] ^ keyStreamByte);
        }
        
        return result;
    }
    
    public byte[] Encrypt(byte[] data, byte[] key)
    {
        return Process(data, key);
    }
    
    public byte[] Decrypt(byte[] data, byte[] key)
    {
        return Process(data, key);
    }
 
    public byte[] GenerateKeyStream(byte[] key, int length)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        if (length < 0)
            throw new ArgumentException("Length must be non-negative", nameof(length));
        
        byte[] S = InitializeSBox(key);
        byte[] keyStream = new byte[length];
        int i = 0, j = 0;
        
        for (int k = 0; k < length; k++)
        {
            keyStream[k] = GenerateKeyStreamByte(S, ref i, ref j);
        }
        
        return keyStream;
    }
}
