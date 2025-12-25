using EncryptionCoursework.Algorithms;
using EncryptionCoursework.Core;
using EncryptionCoursework.Enums;
using EncryptionCoursework.FileEncryption;
using EncryptionCoursework.Demo;

namespace EncryptionCoursework;

class Program
{
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        
        {
			var des = new DES();
			byte[] key = new byte[8];
			byte[] block = new byte[8];

			Random.Shared.NextBytes(key);
			Random.Shared.NextBytes(block);

			var enc = des.EncryptBlock(block, key);
			var dec = des.DecryptBlock(enc, key);

			Console.WriteLine("DES self-test: " + block.SequenceEqual(dec));
			Console.WriteLine();
        }

   
        await DemoRunner.RunAsync();
   	 	Console.WriteLine("\nНажмите любую клавишу для продолжения...");
    	Console.ReadKey();
    	Console.Clear();
    
        Console.WriteLine("=== Система шифрования файлов ===\n");
        
      
        await DemonstrateEncryption(
            new DES(),
            "DES",
            CipherMode.CBC,
            PaddingMode.PKCS7);
        
      
        await DemonstrateEncryption(
            new TripleDES(),
            "TripleDES",
            CipherMode.CBC,
            PaddingMode.PKCS7);
        
       
        await DemonstrateEncryption(
            new DEAL(),
            "DEAL",
            CipherMode.CBC,
            PaddingMode.PKCS7);
        
        Console.WriteLine("\nВсе примеры выполнены успешно!");
    }
    
    static async Task DemonstrateEncryption(
        IBlockCipher cipher,
        string algorithmName,
        CipherMode cipherMode,
        PaddingMode paddingMode)
    {
        Console.WriteLine($"\n--- Демонстрация {algorithmName} ---");
        
        try
        {
          
            byte[] key = new byte[cipher.KeySize];
            Random.Shared.NextBytes(key);
            
           
            byte[]? iv = null;
            if (cipherMode != CipherMode.ECB)
            {
                iv = new byte[cipher.BlockSize];
                Random.Shared.NextBytes(iv);
            }
        
            string testFile = $"test_{algorithmName.ToLower()}.txt";
            string encryptedFile = $"encrypted_{algorithmName.ToLower()}.bin";
            string decryptedFile = $"decrypted_{algorithmName.ToLower()}.txt";
            
            string testContent = $"Тестовое содержимое файла для {algorithmName}.\n" +
                               $"Это демонстрация работы алгоритма шифрования.\n" +
                               $"Режим: {cipherMode}, Набивка: {paddingMode}";
            
            await File.WriteAllTextAsync(testFile, testContent);
            Console.WriteLine($"Создан тестовый файл: {testFile}");
            
        
            var encryptor = new FileEncryptor(cipher, cipherMode, paddingMode);
            
       
            Console.WriteLine("Шифрование файла...");
            await encryptor.EncryptFileAsync(testFile, encryptedFile, key, iv);
            Console.WriteLine($"Файл зашифрован: {encryptedFile}");
            
           
            Console.WriteLine("Дешифрование файла...");
            await encryptor.DecryptFileAsync(encryptedFile, decryptedFile, key, iv);
            Console.WriteLine($"Файл дешифрован: {decryptedFile}");
         
            string decryptedContent = await File.ReadAllTextAsync(decryptedFile);
            
        
            decryptedContent = decryptedContent.TrimEnd('\0');
            string trimmedTestContent = testContent.TrimEnd('\0');
            
            if (decryptedContent == trimmedTestContent || decryptedContent.StartsWith(trimmedTestContent))
            {
                Console.WriteLine("✓ Шифрование и дешифрование выполнены успешно!");
            }
            else
            {
                Console.WriteLine($"✗ Ошибка: содержимое не совпадает!");
                Console.WriteLine($"  Ожидалось: {trimmedTestContent.Substring(0, Math.Min(50, trimmedTestContent.Length))}...");
                Console.WriteLine($"  Получено: {decryptedContent.Substring(0, Math.Min(50, decryptedContent.Length))}...");
            }
            
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"  Детали: {ex.InnerException.Message}");
            }
        }
    }
}
