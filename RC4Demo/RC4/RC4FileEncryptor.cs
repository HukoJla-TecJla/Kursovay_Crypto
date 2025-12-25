namespace RC4Demo.RC4;


public class RC4FileEncryptor
{
    private readonly RC4Algorithm _rc4;
    private readonly int _bufferSize;
    
    public RC4FileEncryptor(int bufferSize = 64 * 1024) 
    {
        _rc4 = new RC4Algorithm();
        _bufferSize = bufferSize;
    }
    
 
    public async Task EncryptFileAsync(
        string inputPath,
        string outputPath,
        byte[] key,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
        if (string.IsNullOrEmpty(outputPath))
            throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        
        await ProcessFileAsync(inputPath, outputPath, key, true, cancellationToken);
    }
    
    public async Task DecryptFileAsync(
        string inputPath,
        string outputPath,
        byte[] key,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
        if (string.IsNullOrEmpty(outputPath))
            throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty", nameof(key));
        
        await ProcessFileAsync(inputPath, outputPath, key, false, cancellationToken);
    }
    
    private async Task ProcessFileAsync(
        string inputPath,
        string outputPath,
        byte[] key,
        bool isEncryption,
        CancellationToken cancellationToken)
    {
        using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, _bufferSize, useAsync: true);
        using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, _bufferSize, useAsync: true);
        
        byte[] buffer = new byte[_bufferSize];
        int bytesRead;
        long totalBytes = 0;
        long fileSize = inputStream.Length;

        byte[] S = InitializeSBox(key);
        int i = 0, j = 0;
        
        while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
        {
          
            byte[] dataToProcess = new byte[bytesRead];
            Array.Copy(buffer, 0, dataToProcess, 0, bytesRead);
            byte[] processed = ProcessBlock(dataToProcess, S, ref i, ref j);
            await outputStream.WriteAsync(processed, 0, processed.Length, cancellationToken);
            
            totalBytes += bytesRead;
        
            if (fileSize > 0)
            {
                double progress = (double)totalBytes / fileSize * 100;
                Console.Write($"\rОбработано: {progress:F1}% ({totalBytes} / {fileSize} байт)");
            }
        }
        
        Console.WriteLine(); 
    }
    
    private static byte[] InitializeSBox(byte[] key)
    {
        byte[] S = new byte[256];
        
        for (int k = 0; k < 256; k++)
        {
            S[k] = (byte)k;
        }
        
        int j = 0;
        for (int k = 0; k < 256; k++)
        {
            j = (j + S[k] + key[k % key.Length]) % 256;
            
            byte temp = S[k];
            S[k] = S[j];
            S[j] = temp;
        }
        
        return S;
    }
    
    private static byte[] ProcessBlock(byte[] data, byte[] S, ref int i, ref int j)
    {
        byte[] result = new byte[data.Length];
        
        for (int k = 0; k < data.Length; k++)
        {
          
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
            int K = S[(S[i] + S[j]) % 256];
            byte keyStreamByte = (byte)K;
            result[k] = (byte)(data[k] ^ keyStreamByte);
        }
        
        return result;
    }
}
