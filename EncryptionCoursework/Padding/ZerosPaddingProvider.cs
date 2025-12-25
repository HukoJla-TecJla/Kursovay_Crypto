using EncryptionCoursework.Core;

namespace EncryptionCoursework.Padding;

public class ZerosPaddingProvider : IPaddingProvider
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (blockSize <= 0) throw new ArgumentException(nameof(blockSize));

        int paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == blockSize)
            paddingLength = 0;

        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);
        return result;
    }

    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (data.Length % blockSize != 0)
            throw new ArgumentException("Invalid padded data length");

        int len = data.Length;
        while (len > 0 && data[len - 1] == 0x00)
            len--;

        byte[] result = new byte[len];
        Array.Copy(data, result, len);
        return result;
    }
}