namespace EncryptionCoursework.Demo;

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using EncryptionCoursework.Algorithms;
using EncryptionCoursework.Enums;
using EncryptionCoursework.FileEncryption;
using EncryptionCoursework.Core;

public static class DemoRunner
{
    public static async Task RunAsync()
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.WriteLine("===== ПОШАГОВАЯ ДЕМОНСТРАЦИЯ =====\n");

        await DemoAlgorithm(
            new DES(),
            "DES",
            CipherMode.ECB,
            PaddingMode.PKCS7);

        await DemoAlgorithm(
            new TripleDES(),
            "TripleDES",
            CipherMode.ECB,
            PaddingMode.PKCS7);

        await DemoAlgorithm(
            new DEAL(),
            "DEAL",
            CipherMode.ECB,
            PaddingMode.PKCS7);

        Console.WriteLine("\n===== КОНЕЦ ДЕМОНСТРАЦИИ =====");
    }

    private static async Task DemoAlgorithm(
        IBlockCipher cipher,
        string name,
        CipherMode cipherMode,
        PaddingMode paddingMode)
    {
        Console.WriteLine($"\n--- {name} ---");

        
        string plainText = "Hello DES demo text!";
        Console.WriteLine("Исходный текст:");
        Console.WriteLine(plainText);

        
        string inputFile = $"demo_{name}_input.txt";
        string encryptedFile = $"demo_{name}_encrypted.bin";
        string decryptedFile = $"demo_{name}_decrypted.txt";

        await File.WriteAllTextAsync(inputFile, plainText, Encoding.UTF8);

       
        byte[] key = new byte[cipher.KeySize];
        Random.Shared.NextBytes(key);

        byte[] iv = new byte[cipher.BlockSize]; 
        

       
        var encryptor = new FileEncryptor(cipher, cipherMode, paddingMode);

        await encryptor.EncryptFileAsync(inputFile, encryptedFile, key, iv);

        byte[] encryptedFileBytes = await File.ReadAllBytesAsync(encryptedFile);

        byte[] cipherTextOnly = cipherMode == CipherMode.ECB
            ? encryptedFileBytes
            : encryptedFileBytes.Skip(cipher.BlockSize).ToArray();

        Console.WriteLine("\nЗашифрованные данные (HEX, без IV):");
        PrintHex(cipherTextOnly);

        Console.WriteLine("Зашифрованные данные (Base64, без IV):");
        Console.WriteLine(Convert.ToBase64String(cipherTextOnly));
        
        // 5️⃣ Дешифрование
        await encryptor.DecryptFileAsync(encryptedFile, decryptedFile, key, iv);

        string decryptedText = await File.ReadAllTextAsync(decryptedFile, Encoding.UTF8);

        Console.WriteLine("\nПосле дешифрования:");
        Console.WriteLine(decryptedText);

       
        Console.WriteLine(
            decryptedText == plainText
                ? "✓ Данные восстановлены корректно"
                : "✗ Ошибка восстановления");

      
        File.Delete(inputFile);
        File.Delete(encryptedFile);
        File.Delete(decryptedFile);
    }

    private static void PrintHex(byte[] data)
    {
        Console.WriteLine(string.Join(" ", data.Select(b => b.ToString("X2"))));
    }
}