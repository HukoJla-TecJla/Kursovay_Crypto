using SerpentDemo.Serpent;
using SerpentDemo.Enums;
using SerpentDemo.CipherModes;
using SerpentDemo.Padding;

namespace SerpentDemo.FileEncryption;


public class SerpentFileEncryptor
{
    private readonly ISerpentCipher _cipher;
    private readonly CipherMode _cipherMode;
    private readonly PaddingMode _paddingMode;
    private readonly IrreduciblePolynomial _polynomial;
    private readonly int _bufferSize;
    private readonly int _maxParallelism;
    
    public SerpentFileEncryptor(
        ISerpentCipher cipher,
        CipherMode cipherMode = CipherMode.CBC,
        PaddingMode paddingMode = PaddingMode.PKCS7,
        IrreduciblePolynomial polynomial = IrreduciblePolynomial.Polynomial_11B,
        int bufferSize = 64 * 1024,
        int? maxParallelism = null)
    {
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        _cipherMode = cipherMode;
        _paddingMode = paddingMode;
        _polynomial = polynomial;
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
        
       
        byte[] unpaddedData;
        try
        {
            unpaddedData = paddingProvider.RemovePadding(decryptedData, _cipher.BlockSize);
        }
        catch (ArgumentException ex)
        {
  
            Console.WriteLine($"\n⚠ Предупреждение: Не удалось удалить набивку: {ex.Message}");
            Console.WriteLine($"  Размер расшифрованных данных: {decryptedData.Length} байт");
            Console.WriteLine($"  Последние 16 байт (hex): {BitConverter.ToString(decryptedData.TakeLast(16).ToArray()).Replace("-", " ")}");
            Console.WriteLine($"  Возможно, проблема в алгоритме Serpent или режиме шифрования.");
            throw new InvalidOperationException(
                "Не удалось удалить набивку. Возможно, данные были неправильно дешифрованы. " +
                "Проверьте правильность ключа, IV и режима шифрования.", ex);
        }
        
        await File.WriteAllBytesAsync(outputPath, unpaddedData, cancellationToken);
    }
    
    private async Task<byte[]> EncryptDataParallelAsync(
        byte[] data,
        byte[] key,
        byte[]? iv,
        ICipherMode mode,
        CancellationToken cancellationToken)
    {
        if (_cipherMode == CipherMode.ECB)
        {
            return await EncryptECBParallelAsync(data, key, cancellationToken);
        }
        
        return await Task.Run(() => mode.Encrypt(data, key, iv, _cipher, _polynomial), cancellationToken);
    }
    
    private async Task<byte[]> DecryptDataParallelAsync(
        byte[] data,
        byte[] key,
        byte[]? iv,
        ICipherMode mode,
        CancellationToken cancellationToken)
    {
        if (_cipherMode == CipherMode.ECB)
        {
            return await DecryptECBParallelAsync(data, key, cancellationToken);
        }
        
        return await Task.Run(() => mode.Decrypt(data, key, iv, _cipher, _polynomial), cancellationToken);
    }
    
    private async Task<byte[]> EncryptECBParallelAsync(
        byte[] data,
        byte[] key,
        CancellationToken cancellationToken)
    {
        int blockCount = data.Length / _cipher.BlockSize;
        byte[] result = new byte[data.Length];
        
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = _maxParallelism,
            CancellationToken = cancellationToken
        };
        
        await Task.Run(() =>
        {
            Parallel.For(0, blockCount, parallelOptions, i =>
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);
                byte[] encrypted = _cipher.EncryptBlock(block, key, _polynomial);
                Array.Copy(encrypted, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);
            });
        }, cancellationToken);
        
        return result;
    }
    
    private async Task<byte[]> DecryptECBParallelAsync(
        byte[] data,
        byte[] key,
        CancellationToken cancellationToken)
    {
        int blockCount = data.Length / _cipher.BlockSize;
        byte[] result = new byte[data.Length];
        
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = _maxParallelism,
            CancellationToken = cancellationToken
        };
        
        await Task.Run(() =>
        {
            Parallel.For(0, blockCount, parallelOptions, i =>
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);
                byte[] decrypted = _cipher.DecryptBlock(block, key, _polynomial);
                Array.Copy(decrypted, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);
            });
        }, cancellationToken);
        
        return result;
    }
}
