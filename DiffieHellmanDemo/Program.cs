using System.Numerics;
using System.Text;
using DiffieHellmanDemo.DiffieHellman;
using DiffieHellmanDemo.SymmetricCipher;

namespace DiffieHellmanDemo;

class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║     Демонстрация протокола Диффи-Хеллмана                   ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();
        

        Console.WriteLine("Выберите размер ключа:");
        Console.WriteLine("1. 256 бит (быстро, для демонстрации)");
        Console.WriteLine("2. 512 бит (рекомендуется)");
        Console.WriteLine("3. 1024 бит (высокая безопасность, медленно)");
        Console.Write("Ваш выбор (1-3, по умолчанию 1): ");
        
        string? keySizeChoice = Console.ReadLine();
        int keySize = keySizeChoice switch
        {
            "2" => 512,
            "3" => 1024,
            _ => 256
        };
        
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 1: ГЕНЕРАЦИЯ ОБЩИХ ПАРАМЕТРОВ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        var dh = new DiffieHellmanProtocol();
        
        Console.WriteLine($"\nГенерация параметров протокола ({keySize} бит)...");
        Console.WriteLine("Это может занять некоторое время...");
        
        var startTime = DateTime.Now;
        DHParameters parameters = dh.GenerateParameters(keySize);
        var endTime = DateTime.Now;
        
        Console.WriteLine($"✓ Параметры сгенерированы за {(endTime - startTime).TotalSeconds:F2} секунд");
        Console.WriteLine();
        
        Console.WriteLine("ОБЩИЕ ПАРАМЕТРЫ (известны обеим сторонам):");
        Console.WriteLine($"  Простое число p:");
        Console.WriteLine($"    Размер: {parameters.Prime.GetBitLength()} бит");
        Console.WriteLine($"    Значение: {FormatBigInteger(parameters.Prime)}");
        Console.WriteLine();
        Console.WriteLine($"  Генератор g: {parameters.Generator}");
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 2: СОЗДАНИЕ УЧАСТНИКОВ ПРОТОКОЛА");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
       
        Console.WriteLine("\nСоздание участника Алиса (Alice)...");
        DHParticipant alice = dh.CreateParticipant(parameters, "Alice");
        Console.WriteLine($"✓ Алиса создана");
        Console.WriteLine($"  Приватный ключ a: {FormatBigInteger(alice.PrivateKey)}");
        Console.WriteLine($"  Публичный ключ A = g^a mod p: {FormatBigInteger(alice.PublicKey)}");
        Console.WriteLine();
        
        Console.WriteLine("Создание участника Боб (Bob)...");
        DHParticipant bob = dh.CreateParticipant(parameters, "Bob");
        Console.WriteLine($"✓ Боб создан");
        Console.WriteLine($"  Приватный ключ b: {FormatBigInteger(bob.PrivateKey)}");
        Console.WriteLine($"  Публичный ключ B = g^b mod p: {FormatBigInteger(bob.PublicKey)}");
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 3: ОБМЕН ПУБЛИЧНЫМИ КЛЮЧАМИ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        Console.WriteLine("\nАлиса отправляет свой публичный ключ A Бобу:");
        Console.WriteLine($"  A = {FormatBigInteger(alice.PublicKey)}");
        Console.WriteLine();
        
        Console.WriteLine("Боб отправляет свой публичный ключ B Алисе:");
        Console.WriteLine($"  B = {FormatBigInteger(bob.PublicKey)}");
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 4: ВЫЧИСЛЕНИЕ ОБЩЕГО СЕКРЕТНОГО КЛЮЧА");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        Console.WriteLine("\nАлиса вычисляет общий секретный ключ:");
        Console.WriteLine($"  K = B^a mod p = {FormatBigInteger(bob.PublicKey)}^a mod p");
        BigInteger aliceSharedSecret = dh.ComputeSharedSecret(alice, bob.PublicKey, parameters);
        Console.WriteLine($"  K = {FormatBigInteger(aliceSharedSecret)}");
        Console.WriteLine();
        
        Console.WriteLine("Боб вычисляет общий секретный ключ:");
        Console.WriteLine($"  K = A^b mod p = {FormatBigInteger(alice.PublicKey)}^b mod p");
        BigInteger bobSharedSecret = dh.ComputeSharedSecret(bob, alice.PublicKey, parameters);
        Console.WriteLine($"  K = {FormatBigInteger(bobSharedSecret)}");
        Console.WriteLine();
        
        Console.WriteLine($"Ключи совпадают: {(aliceSharedSecret == bobSharedSecret ? "✓ ДА" : "✗ НЕТ")}");
        Console.WriteLine();
        
        if (aliceSharedSecret != bobSharedSecret)
        {
            Console.WriteLine("ОШИБКА: Ключи не совпадают!");
            return;
        }
        
        BigInteger sharedSecret = aliceSharedSecret;
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 5: ИСПОЛЬЗОВАНИЕ КЛЮЧА ДЛЯ СИММЕТРИЧНОГО ШИФРОВАНИЯ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        
        
        Console.WriteLine("\nВведите сообщение для шифрования (или нажмите Enter для использования примера):");
        string? inputMessage = Console.ReadLine();
        
        if (string.IsNullOrWhiteSpace(inputMessage))
        {
            inputMessage = "Секретное сообщение, зашифрованное ключом из Диффи-Хеллмана!";
            Console.WriteLine($"Используется пример сообщения: {inputMessage}");
        }
        
        Console.WriteLine();
        

        const int symmetricKeySize = 8; 
        byte[] symmetricKey = SimpleDES.DeriveKey(sharedSecret, symmetricKeySize);
        
        Console.WriteLine("Преобразование общего секретного ключа в ключ для симметричного шифрования:");
        Console.WriteLine($"  Общий секрет: {FormatBigInteger(sharedSecret)}");
        Console.WriteLine($"  Ключ для шифрования (hex): {BitConverter.ToString(symmetricKey).Replace("-", " ")}");
        Console.WriteLine($"  Ключ для шифрования (dec): {string.Join(" ", symmetricKey)}");
        Console.WriteLine();
        
        
        byte[] messageBytes = Encoding.UTF8.GetBytes(inputMessage);
        
        Console.WriteLine("ИСХОДНОЕ СООБЩЕНИЕ:");
        Console.WriteLine($"  Текст: {inputMessage}");
        Console.WriteLine($"  Размер: {messageBytes.Length} байт");
        Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(messageBytes).Replace("-", " ")}");
        Console.WriteLine();
        
        Console.WriteLine("Шифрование сообщения Алисой...");
        byte[] encrypted = SimpleDES.Encrypt(messageBytes, symmetricKey);
        Console.WriteLine($"✓ Сообщение зашифровано");
        Console.WriteLine();
        
        Console.WriteLine("ЗАШИФРОВАННОЕ СООБЩЕНИЕ:");
        Console.WriteLine($"  Размер: {encrypted.Length} байт");
        Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(encrypted).Replace("-", " ")}");
        Console.WriteLine();
        
        Console.WriteLine("Отправка зашифрованного сообщения Бобу...");
        Console.WriteLine();
        
        Console.WriteLine("Дешифрование сообщения Бобом...");
        byte[] decrypted = SimpleDES.Decrypt(encrypted, symmetricKey);
        string decryptedMessage = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"✓ Сообщение расшифровано");
        Console.WriteLine();
        
        Console.WriteLine("РАСШИФРОВАННОЕ СООБЩЕНИЕ:");
        Console.WriteLine($"  Текст: {decryptedMessage}");
        Console.WriteLine($"  Размер: {decrypted.Length} байт");
        Console.WriteLine($"  В байтах (hex): {BitConverter.ToString(decrypted).Replace("-", " ")}");
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ШАГ 6: РЕЗУЛЬТАТ");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine($"\nИсходное сообщение:  {inputMessage}");
        Console.WriteLine($"Расшифрованное:      {decryptedMessage}");
        Console.WriteLine($"\nСообщения совпадают: {(inputMessage == decryptedMessage ? "✓ ДА" : "✗ НЕТ")}");
        Console.WriteLine();
        
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("ИТОГОВАЯ СХЕМА ПРОТОКОЛА:");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine();
        Console.WriteLine("1. Генерация общих параметров (p, g)");
        Console.WriteLine("2. Алиса выбирает приватный ключ a, вычисляет A = g^a mod p");
        Console.WriteLine("3. Боб выбирает приватный ключ b, вычисляет B = g^b mod p");
        Console.WriteLine("4. Обмен публичными ключами A и B");
        Console.WriteLine("5. Алиса вычисляет K = B^a mod p");
        Console.WriteLine("6. Боб вычисляет K = A^b mod p");
        Console.WriteLine("7. Обе стороны получают одинаковый ключ K");
        Console.WriteLine("8. Использование K для симметричного шифрования");
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
