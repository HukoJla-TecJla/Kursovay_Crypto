using System.Numerics;

namespace RSADemo.RSA;

internal static class PrimeGenerator
{
    private static readonly Random _random = new();
    
    public static BigInteger GeneratePrime(int bitLength)
    {
        if (bitLength < 2)
            throw new ArgumentException("Bit length must be at least 2", nameof(bitLength));
        
        BigInteger candidate;
        int attempts = 0;
        const int maxAttempts = 1000;
        
        do
        {
            candidate = GenerateRandomOdd(bitLength);
            attempts++;
            
            if (attempts > maxAttempts)
                throw new InvalidOperationException("Failed to generate prime after maximum attempts");
        }
        while (!IsProbablyPrime(candidate, 20));
        
        return candidate;
    }
    
    private static BigInteger GenerateRandomOdd(int bitLength)
    {
        byte[] bytes = new byte[(bitLength + 7) / 8];
        _random.NextBytes(bytes);
     
        int bitsInLastByte = bitLength % 8;
        if (bitsInLastByte == 0) bitsInLastByte = 8;
        bytes[0] = (byte)(bytes[0] | (1 << (bitsInLastByte - 1)));
  
        bytes[bytes.Length - 1] |= 1;
        
        BigInteger result = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
  
        BigInteger mask = (BigInteger.One << bitLength) - 1;
        result &= mask;

        if (result.IsEven)
            result |= BigInteger.One;
        
        return result;
    }

    private static bool IsProbablyPrime(BigInteger n, int k)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n.IsEven) return false;
   
        BigInteger d = n - 1;
        int r = 0;
        while (d.IsEven)
        {
            d >>= 1;
            r++;
        }
        
        for (int i = 0; i < k; i++)
        {
            BigInteger a = GenerateRandomBigInteger(2, n - 2);
            BigInteger x = BigInteger.ModPow(a, d, n);
            
            if (x == 1 || x == n - 1)
                continue;
            
            bool composite = true;
            for (int j = 0; j < r - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    composite = false;
                    break;
                }
            }
            
            if (composite)
                return false;
        }
        
        return true;
    }
    
    private static BigInteger GenerateRandomBigInteger(BigInteger min, BigInteger max)
    {
        BigInteger range = max - min;
        int byteCount = range.GetByteCount();
        byte[] bytes = new byte[byteCount];
        _random.NextBytes(bytes);
        
        BigInteger randomValue = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        randomValue %= range;
        randomValue += min;
        
        return randomValue;
    }
}
