using System.Text;
using SerpentDemo.Serpent;
using SerpentDemo.Enums;
using SerpentDemo.FileEncryption;

namespace SerpentDemo;

class Program
{
    static async Task Main(string[] args)
    {
        
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║          Демонстрация алгоритма Serpent                     ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();
        
        var serpent = new SerpentCipher();
        
       
        Console.WriteLine("Выберите неприводимый полином над полем GF(2^8):");
        Console.WriteLine("1. 0x11D (x^8 + x^4 + x^3 + x^2 + 1)");
        Console.WriteLine("2. 0x11B (x^8 + x^4 + x^3 + x + 1) - используется в AES");
        Console.WriteLine("3. 0x12B (x^8 + x^5 + x^3 + x + 1)");
        Console.WriteLine("4. 0x12D (x^8 + x^5 + x^3 + x^2 + 1)");
        Console.WriteLine("5. 0x14D (x^8 + x^6 + x^3 + x^2 + 1)");
        Console.WriteLine("6. 0x15B (x^8 + x^6 + x^4 + x^3 + x + 1)");
        Console.WriteLine("7. 0x163 (x^8 + x^6 + x^5 + x + 1)");
        Console.WriteLine("8. 0x1F5 (x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1)");
        Console.Write("Ваш выбор (1-8, по умолчанию 2): ");
        
        string? polyChoice = Console.ReadLine();
        IrreduciblePolynomial polynomial = polyChoice switch
        {
            "1" => IrreduciblePolynomial.Polynomial_11D,
            "3" => IrreduciblePolynomial.Polynomial_12B,
            "4" => IrreduciblePolynomial.Polynomial_12D,
            "5" => IrreduciblePolynomial.Polynomial_14D,
            "6" => IrreduciblePolynomial.Polynomial_15B,
            "7" => IrreduciblePolynomial.Polynomial_163,
            "8" => IrreduciblePolynomial.Polynomial_1F5,
            _ => IrreduciblePolynomial.Polynomial_11B
        };
        
        Console.WriteLine($"Выбран полином: 0x{(int)polynomial:X}");
        Console.WriteLine();
        
       
        Console.WriteLine("Выберите режим шифрования:");
        Console.WriteLine("1. ECB (Electronic Codebook)");
        Console.WriteLine("2. CBC (Cipher Block Chaining)");
        Console.WriteLine("3. PCBC (Propagating Cipher Block Chaining)");
        Console.WriteLine("4. CFB (Cipher Feedback)");
        Console.WriteLine("5. OFB (Output Feedback)");
        Console.WriteLine("6. CTR (Counter)");
        Console.WriteLine("7. Random Delta");
        Console.Write("Ваш выбор (1-7, по умолчанию 2): ");
        
        string? modeChoice = Console.ReadLine();
        CipherMode cipherMode = modeChoice switch
        {
            "1" => CipherMode.ECB,
            "3" => CipherMode.PCBC,
            "4" => CipherMode.CFB,
            "5" => CipherMode.OFB,
            "6" => CipherMode.CTR,
            "7" => CipherMode.RandomDelta,
            _ => CipherMode.CBC
        };
        
        Console.WriteLine($"Выбран режим: {cipherMode}");
        Console.WriteLine();
        
    
        Console.WriteLine("Выберите режим набивки:");
        Console.WriteLine("1. Zeros");
        Console.WriteLine("2. ANSI X9.23");
        Console.WriteLine("3. PKCS7");
        Console.WriteLine("4. ISO 10126");
        Console.Write("Ваш выбор (1-4, по умолчанию 3): ");
        
        string? paddingChoice = Console.ReadLine();
        PaddingMode paddingMode = paddingChoice switch
        {
            "1" => PaddingMode.Zeros,
            "2" => PaddingMode.AnsiX923,
            "4" => PaddingMode.ISO10126,
            _ => PaddingMode.PKCS7
        };
        
        Console.WriteLine($"Выбран режим набивки: {paddingMode}");
        Console.WriteLine();
        
        
        Console.WriteLine("Генерация ключа...");
        byte[] key = new byte[serpent.KeySize];
        Random.Shared.NextBytes(key);
        Console.WriteLine($"Ключ (hex): {BitConverter.ToString(key).Replace("-", " ")}");
        Console.WriteLine($"Размер ключа: {key.Length} байт ({key.Length * 8} бит)");
        Console.WriteLine();
        
       
        byte[]? iv = null;
        if (cipherMode != CipherMode.ECB)
        {
            iv = new byte[serpent.BlockSize];
            Random.Shared.NextBytes(iv);
            Console.WriteLine($"IV (hex): {BitConverter.ToString(iv).Replace("-", " ")}");
            Console.WriteLine();
        }
        
        
        Console.WriteLine("Введите сообщение для шифрования (или нажмите Enter для использования примера):");
        string? inputMessage = Console.ReadLine();
        
        if (string.IsNullOrWhiteSpace(inputMessage))
        {
            inputMessage = "Привет! Это тестовое сообщение для демонстрации Serpent шифрования.";
            Console.WriteLine($"Используется пример сообщения: {inputMessage}");
        }
        
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 1: ИСХОДНЫЕ ДАННЫЕ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        byte[] messageBytes = Encoding.UTF8.GetBytes(inputMessage);
        
        Console.WriteLine($"\nИСХОДНОЕ СООБЩЕНИЕ:");
        Console.WriteLine($"  Текст: {inputMessage}");
        Console.WriteLine($"  Размер: {messageBytes.Length} байт");
        Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(messageBytes).Replace("-", " ")}");
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 2: ТЕСТИРОВАНИЕ АЛГОРИТМА SERPENT");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
       
        Console.WriteLine("\nТестирование шифрования/дешифрования одного блока...");
        byte[] testBlock = new byte[serpent.BlockSize];
        Random.Shared.NextBytes(testBlock);
        Console.WriteLine($"  Тестовый блок (hex): {BitConverter.ToString(testBlock).Replace("-", " ")}");
        
        byte[] encryptedBlock = serpent.EncryptBlock(testBlock, key, polynomial);
        Console.WriteLine($"  Зашифрованный блок (hex): {BitConverter.ToString(encryptedBlock).Replace("-", " ")}");
        
        byte[] decryptedBlock = serpent.DecryptBlock(encryptedBlock, key, polynomial);
        Console.WriteLine($"  Расшифрованный блок (hex): {BitConverter.ToString(decryptedBlock).Replace("-", " ")}");
        
        bool blockTest = testBlock.SequenceEqual(decryptedBlock);
        Console.WriteLine($"  Блоки совпадают: {(blockTest ? "✓ ДА" : "✗ НЕТ")}");
        
        if (!blockTest)
        {
            Console.WriteLine("\n⚠ ВНИМАНИЕ: Алгоритм Serpent работает неправильно!");
            Console.WriteLine("  Продолжение может привести к ошибкам...");
            Console.WriteLine("  Попробуйте использовать другой режим шифрования (например, ECB)");
        }
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 3: ШИФРОВАНИЕ ФАЙЛА");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        var fileEncryptor = new SerpentFileEncryptor(
            serpent,
            cipherMode,
            paddingMode,
            polynomial
        );
        
        
        string testFile = "serpent_test.txt";
        string encryptedFile = "serpent_encrypted.bin";
        string decryptedFile = "serpent_decrypted.txt";
        
        try
        {
            await File.WriteAllTextAsync(testFile, inputMessage);
            Console.WriteLine($"\nСоздан тестовый файл: {testFile}");
            
            Console.WriteLine("Шифрование файла...");
            await fileEncryptor.EncryptFileAsync(testFile, encryptedFile, key, iv);
            Console.WriteLine($"✓ Файл зашифрован: {encryptedFile}");
            
            FileInfo encryptedInfo = new FileInfo(encryptedFile);
            Console.WriteLine($"  Размер зашифрованного файла: {encryptedInfo.Length} байт");
            
            byte[] encryptedData = await File.ReadAllBytesAsync(encryptedFile);
            Console.WriteLine($"  Зашифрованные данные (первые 32 байта, hex): {BitConverter.ToString(encryptedData.Take(32).ToArray()).Replace("-", " ")}");
            Console.WriteLine();
            
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("ШАГ 4: ДЕШИФРОВАНИЕ ФАЙЛА");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            
            Console.WriteLine("\nДешифрование файла...");
            await fileEncryptor.DecryptFileAsync(encryptedFile, decryptedFile, key, iv);
            Console.WriteLine($"✓ Файл дешифрован: {decryptedFile}");
            
            string decryptedMessage = await File.ReadAllTextAsync(decryptedFile);
            Console.WriteLine();
            
            Console.WriteLine("РАСШИФРОВАННОЕ СООБЩЕНИЕ:");
            Console.WriteLine($"  Текст: {decryptedMessage}");
            Console.WriteLine();
            
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("ШАГ 5: РЕЗУЛЬТАТ");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine($"\nИсходное сообщение:  {inputMessage}");
            Console.WriteLine($"Расшифрованное:      {decryptedMessage}");
            Console.WriteLine($"\nСообщения совпадают: {(inputMessage == decryptedMessage ? "✓ ДА" : "✗ НЕТ")}");
            Console.WriteLine();
            
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("ИТОГОВАЯ ИНФОРМАЦИЯ:");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine($"  Алгоритм: Serpent");
            Console.WriteLine($"  Размер блока: {serpent.BlockSize} байт (128 бит)");
            Console.WriteLine($"  Размер ключа: {key.Length} байт ({key.Length * 8} бит)");
            Console.WriteLine($"  Неприводимый полином: 0x{(int)polynomial:X}");
            Console.WriteLine($"  Режим шифрования: {cipherMode}");
            Console.WriteLine($"  Режим набивки: {paddingMode}");
            if (iv != null)
            {
                Console.WriteLine($"  IV: {BitConverter.ToString(iv).Replace("-", " ")}");
            }
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nОшибка: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"  Детали: {ex.InnerException.Message}");
            }
            Console.WriteLine($"  Тип ошибки: {ex.GetType().Name}");
            Console.WriteLine("\nПопробуйте:");
            Console.WriteLine("  1. Использовать другой режим шифрования (например, CBC вместо PCBC)");
            Console.WriteLine("  2. Использовать другой режим набивки (например, PKCS7)");
            Console.WriteLine("  3. Проверить, что алгоритм Serpent работает корректно (см. тест выше)");
        }
        finally
        {
            // Очистка (закомментировано для возможности проверки)
            // File.Delete(testFile);
            // File.Delete(encryptedFile);
            // File.Delete(decryptedFile);
        }
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("Демонстрация завершена!");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        try
        {
            Console.WriteLine("\nНажмите любую клавишу для выхода...");
            Console.ReadKey();
        }
        catch (InvalidOperationException)
        {
            
        }
    }
}
