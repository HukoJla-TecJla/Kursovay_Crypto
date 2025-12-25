using EncryptionCoursework.Core;
using EncryptionCoursework.Enums;
using EncryptionCoursework.Padding;
using EncryptionCoursework.CipherModes;

namespace EncryptionCoursework.FileEncryption;


public class FileEncryptor : IFileEncryptor
{
    private readonly IBlockCipher _cipher;
    private readonly CipherMode _cipherMode;
    private readonly PaddingMode _paddingMode;
    private readonly int _bufferSize;
    private readonly int _maxParallelism;
    
    public FileEncryptor(
        IBlockCipher cipher,
        CipherMode cipherMode = CipherMode.CBC,
        PaddingMode paddingMode = PaddingMode.PKCS7,
        int bufferSize = 64 * 1024, // 64 KB
        int? maxParallelism = null)
    {
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        _cipherMode = cipherMode;
        _paddingMode = paddingMode;
        _bufferSize = bufferSize;
        _maxParallelism = maxParallelism ?? Environment.ProcessorCount;
    }
    
    public async Task EncryptFileAsync(
        string inputPath,
        string outputPath,
        byte[] key,
        byte[]? iv = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
        if (string.IsNullOrEmpty(outputPath))
            throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        
        var mode = CipherModeFactory.Create(_cipherMode);
        if (mode.RequiresIV && (iv == null || iv.Length != _cipher.BlockSize))
        {
            throw new ArgumentException($"IV must be provided and be {_cipher.BlockSize} bytes for {_cipherMode} mode");
        }
        
        
        var paddingProvider = PaddingProviderFactory.Create(_paddingMode);


        byte[] fileData = await File.ReadAllBytesAsync(inputPath, cancellationToken);


        byte[] paddedData = paddingProvider.AddPadding(fileData, _cipher.BlockSize);


        byte[] encryptedData = await EncryptDataParallelAsync(
            paddedData,
            key,
            iv,
            mode,
            cancellationToken);

        await File.WriteAllBytesAsync(outputPath, encryptedData, cancellationToken);
    }
    
    public async Task DecryptFileAsync(
        string inputPath,
        string outputPath,
        byte[] key,
        byte[]? iv = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
        if (string.IsNullOrEmpty(outputPath))
            throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        
        var mode = CipherModeFactory.Create(_cipherMode);
        if (mode.RequiresIV && (iv == null || iv.Length != _cipher.BlockSize))
        {
            throw new ArgumentException($"IV must be provided and be {_cipher.BlockSize} bytes for {_cipherMode} mode");
        }
        
        var paddingProvider = PaddingProviderFactory.Create(_paddingMode);

      
        byte[] encryptedData = await File.ReadAllBytesAsync(inputPath, cancellationToken);
        
        if (encryptedData.Length % _cipher.BlockSize != 0)
            throw new ArgumentException("Encrypted data length must be multiple of block size");
        
        
        byte[] decryptedData = await DecryptDataParallelAsync(
            encryptedData,
            key,
            iv,
            mode,
            cancellationToken);
        byte[] unpaddedData = paddingProvider.RemovePadding(decryptedData, _cipher.BlockSize);

       
        await File.WriteAllBytesAsync(outputPath, unpaddedData, cancellationToken);
    }
    
    private async Task<byte[]> EncryptDataParallelAsync(
        byte[] data,
        byte[] key,
        byte[]? iv,
        ICipherMode mode,
        CancellationToken cancellationToken)
    {
 
        return await Task.Run(() => mode.Encrypt(data, key, iv, _cipher), cancellationToken);
    }
    
    private async Task<byte[]> DecryptDataParallelAsync(
        byte[] data,
        byte[] key,
        byte[]? iv,
        ICipherMode mode,
        CancellationToken cancellationToken)
    {
       
        return await Task.Run(() => mode.Decrypt(data, key, iv, _cipher), cancellationToken);
    }
}
