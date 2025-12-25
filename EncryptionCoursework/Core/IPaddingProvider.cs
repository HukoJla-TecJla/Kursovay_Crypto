namespace EncryptionCoursework.Core;

public interface IPaddingProvider
{
    byte[] AddPadding(byte[] data, int blockSize);
    byte[] RemovePadding(byte[] data, int blockSize);
}
