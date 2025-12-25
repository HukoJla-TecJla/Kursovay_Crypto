using System.Numerics;
using System.Text;
using RSADemo.RSA;

namespace RSADemo;

class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║          Демонстрация алгоритма RSA                        ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();
        
        Console.WriteLine("Введите сообщение для шифрования (или нажмите Enter для использования примера):");
        string? inputMessage = Console.ReadLine();
        
        if (string.IsNullOrWhiteSpace(inputMessage))
        {
            inputMessage = "Привет! Это тестовое сообщение для демонстрации RSA шифрования.";
            Console.WriteLine($"Используется пример сообщения: {inputMessage}");
        }
        
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 1: ГЕНЕРАЦИЯ КЛЮЧЕЙ RSA");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        Console.WriteLine("\nВыберите размер ключа:");
        Console.WriteLine("1. 512 бит (быстро, для демонстрации)");
        Console.WriteLine("2. 1024 бит (рекомендуется)");
        Console.WriteLine("3. 2048 бит (высокая безопасность, медленно)");
        Console.Write("Ваш выбор (1-3, по умолчанию 1): ");
        
        string? keySizeChoice = Console.ReadLine();
        int keySize = keySizeChoice switch
        {
            "2" => 1024,
            "3" => 2048,
            _ => 512
        };
        
        Console.WriteLine($"\nГенерация ключей RSA ({keySize} бит)...");
        Console.WriteLine("Это может занять некоторое время...");
        
        var keyGenerator = new RSAKeyGenerator();
        var publicExponent = new BigInteger(65537);
        
        var startTime = DateTime.Now;
        RSAParameters keyPair = keyGenerator.GenerateKeyPair(keySize, publicExponent);
        var endTime = DateTime.Now;
        
        Console.WriteLine($"✓ Ключи сгенерированы за {(endTime - startTime).TotalSeconds:F2} секунд");
        Console.WriteLine();
        
        Console.WriteLine("ПАРАМЕТРЫ КЛЮЧА:");
        Console.WriteLine($"  Модуль (n):");
        Console.WriteLine($"    Размер: {keyPair.Modulus.GetBitLength()} бит");
        Console.WriteLine($"    Значение: {FormatBigInteger(keyPair.Modulus)}");
        Console.WriteLine();
        Console.WriteLine($"  Публичная экспонента (e): {keyPair.PublicExponent}");
        Console.WriteLine($"  Приватная экспонента (d):");
        Console.WriteLine($"    Размер: {keyPair.PrivateExponent!.Value.GetBitLength()} бит");
        Console.WriteLine($"    Значение: {FormatBigInteger(keyPair.PrivateExponent.Value)}");
        Console.WriteLine();
        Console.WriteLine($"  Простые числа:");
        Console.WriteLine($"    p: {FormatBigInteger(keyPair.PrimeP!.Value)}");
        Console.WriteLine($"    q: {FormatBigInteger(keyPair.PrimeQ!.Value)}");
        Console.WriteLine();
        Console.WriteLine($"  Защита от атаки Винера: {(keyGenerator.IsVulnerableToWienerAttack(keyPair) ? "✗ НЕТ" : "✓ ДА")}");
        Console.WriteLine();
        
        RSAParameters publicKey = new RSAParameters
        {
            Modulus = keyPair.Modulus,
            PublicExponent = keyPair.PublicExponent
        };
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 2: ШИФРОВАНИЕ СООБЩЕНИЯ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        var rsa = new RSAAlgorithm();
        byte[] messageBytes = Encoding.UTF8.GetBytes(inputMessage);
        
        Console.WriteLine($"\nИСХОДНОЕ СООБЩЕНИЕ:");
        Console.WriteLine($"  Текст: {inputMessage}");
        Console.WriteLine($"  Размер: {messageBytes.Length} байт");
        Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(messageBytes).Replace("-", " ")}");
        Console.WriteLine($"  В байтах (dec): {string.Join(" ", messageBytes)}");
        Console.WriteLine();
        
        int maxBlockSize = rsa.GetMaxBlockSize(keyPair);
        Console.WriteLine($"  Максимальный размер блока для шифрования: {maxBlockSize} байт");
        
        List<byte[]> encryptedBlocks = new List<byte[]>();
        List<byte[]> decryptedBlocks = new List<byte[]>();
        
        if (messageBytes.Length > maxBlockSize)
        {
            Console.WriteLine($"\nСообщение слишком большое, разбиваем на блоки...");
            
            for (int i = 0; i < messageBytes.Length; i += maxBlockSize)
            {
                int blockSize = Math.Min(maxBlockSize, messageBytes.Length - i);
                byte[] block = new byte[blockSize];
                Array.Copy(messageBytes, i, block, 0, blockSize);
                
                Console.WriteLine($"\n  Блок {encryptedBlocks.Count + 1}:");
                Console.WriteLine($"    Размер: {blockSize} байт");
                Console.WriteLine($"    Данные (hex): {BitConverter.ToString(block).Replace("-", " ")}");
                
                byte[] encrypted = rsa.Encrypt(block, publicKey);
                encryptedBlocks.Add(encrypted);
                
                Console.WriteLine($"    Зашифровано: {encrypted.Length} байт");
                Console.WriteLine($"    Зашифрованные данные (hex): {BitConverter.ToString(encrypted).Replace("-", " ")}");
                
                byte[] decrypted = rsa.Decrypt(encrypted, keyPair);
                decryptedBlocks.Add(decrypted);
                
                Console.WriteLine($"    Расшифровано: {decrypted.Length} байт");
                Console.WriteLine($"    Расшифрованные данные (hex): {BitConverter.ToString(decrypted).Replace("-", " ")}");
            }
        }
        else
        {
            Console.WriteLine("\nШифрование одного блока...");
            
           
            byte[] encrypted = rsa.Encrypt(messageBytes, publicKey);
            encryptedBlocks.Add(encrypted);
            
            Console.WriteLine($"\nЗАШИФРОВАННОЕ СООБЩЕНИЕ:");
            Console.WriteLine($"  Размер: {encrypted.Length} байт");
            Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(encrypted).Replace("-", " ")}");
            Console.WriteLine($"  В байтах (dec): {string.Join(" ", encrypted)}");
            
        
            BigInteger encryptedBigInt = new BigInteger(encrypted, isUnsigned: true, isBigEndian: true);
            Console.WriteLine($"  Как число (BigInteger): {encryptedBigInt}");
            Console.WriteLine();
            
          
            Console.WriteLine("Дешифрование...");
            byte[] decrypted = rsa.Decrypt(encrypted, keyPair);
            decryptedBlocks.Add(decrypted);
            
            Console.WriteLine($"\nРАСШИФРОВАННОЕ СООБЩЕНИЕ:");
            Console.WriteLine($"  Размер: {decrypted.Length} байт");
            Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(decrypted).Replace("-", " ")}");
            Console.WriteLine($"  В байтах (dec): {string.Join(" ", decrypted)}");
        }
        
        
        int totalLength = decryptedBlocks.Sum(b => b.Length);
        byte[] decryptedBytes = new byte[totalLength];
        int offset = 0;
        foreach (var block in decryptedBlocks)
        {
            Array.Copy(block, 0, decryptedBytes, offset, block.Length);
            offset += block.Length;
        }
        
        string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
        
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 3: РЕЗУЛЬТАТ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine($"\nИсходное сообщение:  {inputMessage}");
        Console.WriteLine($"Расшифрованное:      {decryptedMessage}");
        Console.WriteLine($"\nСообщения совпадают: {(inputMessage == decryptedMessage ? "✓ ДА" : "✗ НЕТ")}");
        Console.WriteLine();
        
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 4: ДЕМОНСТРАЦИЯ АТАКИ ВИНЕРА");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        var wienerAttack = new WienerAttack();
        bool isVulnerable = wienerAttack.IsVulnerable(publicKey);
        
        Console.WriteLine($"\nКлюч уязвим к атаке Винера: {(isVulnerable ? "ДА" : "НЕТ")}");
        
        if (isVulnerable)
        {
            Console.WriteLine("\nПопытка выполнить атаку...");
            BigInteger? recoveredD = wienerAttack.Attack(publicKey);
            
            if (recoveredD != null)
            {
                Console.WriteLine($"✓ Атака успешна!");
                Console.WriteLine($"  Восстановленная приватная экспонента: {FormatBigInteger(recoveredD.Value)}");
                Console.WriteLine($"  Оригинальная приватная экспонента:   {FormatBigInteger(keyPair.PrivateExponent!.Value)}");
                Console.WriteLine($"  Экспоненты совпадают: {(recoveredD == keyPair.PrivateExponent ? "✓ ДА" : "✗ НЕТ")}");
            }
            else
            {
                Console.WriteLine("✗ Атака не удалась (ключ защищен или атака не применима)");
            }
        }
        else
        {
            Console.WriteLine("Ключ защищен от атаки Винера благодаря проверке при генерации.");
        }
        
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("Демонстрация завершена!");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("\nНажмите любую клавишу для выхода...");
        Console.ReadKey();
    }
    
    private static string FormatBigInteger(BigInteger value)
    {
        string str = value.ToString();
        if (str.Length > 60)
        {
            return $"{str.Substring(0, 30)}...{str.Substring(str.Length - 30)} ({str.Length} цифр)";
        }
        return str;
    }
}
