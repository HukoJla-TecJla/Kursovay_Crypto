using EncryptionCoursework.Core;

namespace EncryptionCoursework.Padding;

public class PKCS7PaddingProvider : IPaddingProvider
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (blockSize <= 0 || blockSize > 255)
            throw new ArgumentException("Block size must be between 1 and 255", nameof(blockSize));

        int paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == 0)
            paddingLength = blockSize;

        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);

        for (int i = data.Length; i < result.Length; i++)
            result[i] = (byte)paddingLength;

        return result;
    }

    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (blockSize <= 0) throw new ArgumentException(nameof(blockSize));
        if (data.Length == 0 || data.Length % blockSize != 0)
            throw new ArgumentException("Invalid padded data length");

        int paddingLength = data[^1];

        if (paddingLength < 1 || paddingLength > blockSize)
            throw new ArgumentException("Invalid padding");

        for (int i = data.Length - paddingLength; i < data.Length; i++)
        {
            if (data[i] != paddingLength)
                throw new ArgumentException("Invalid padding");
        }

        byte[] result = new byte[data.Length - paddingLength];
        Array.Copy(data, result, result.Length);
        return result;
    }
}