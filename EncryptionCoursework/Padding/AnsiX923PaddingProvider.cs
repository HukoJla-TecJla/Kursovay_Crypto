using EncryptionCoursework.Core;

namespace EncryptionCoursework.Padding;


public class AnsiX923PaddingProvider : IPaddingProvider
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (blockSize <= 0) throw new ArgumentException("Block size must be positive", nameof(blockSize));
        
        int paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == blockSize) paddingLength = 0;
        
        if (paddingLength == 0) return data;
        
        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, result, 0, data.Length);
        
      
        result[result.Length - 1] = (byte)paddingLength;
        
        return result;
    }
    
    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (blockSize <= 0) throw new ArgumentException("Block size must be positive", nameof(blockSize));
        if (data.Length % blockSize != 0) throw new ArgumentException("Data length must be multiple of block size");
        if (data.Length == 0) throw new ArgumentException("Data cannot be empty");
        
        int paddingLength = data[data.Length - 1];
        
        if (paddingLength == 0 || paddingLength > blockSize)
            throw new ArgumentException("Invalid padding");
        
       
        for (int i = data.Length - paddingLength; i < data.Length - 1; i++)
        {
            if (data[i] != 0)
                throw new ArgumentException("Invalid padding");
        }
        
        int originalLength = data.Length - paddingLength;
        byte[] result = new byte[originalLength];
        Array.Copy(data, 0, result, 0, originalLength);
        return result;
    }
}
