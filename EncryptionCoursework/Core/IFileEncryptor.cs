namespace EncryptionCoursework.Core;


public interface IFileEncryptor
{
    Task EncryptFileAsync(string inputPath, string outputPath, byte[] key, byte[]? iv = null, CancellationToken cancellationToken = default);
    Task DecryptFileAsync(string inputPath, string outputPath, byte[] key, byte[]? iv = null, CancellationToken cancellationToken = default);
}
