using System.Numerics;

namespace RSADemo.RSA;


public class RSAKeyGenerator : IRSAKeyGenerator
{
    private static readonly BigInteger DefaultPublicExponent = new BigInteger(65537);
    
    public RSAParameters GenerateKeyPair(int keySize, BigInteger publicExponent)
    {
        if (keySize < 512)
            throw new ArgumentException("Key size must be at least 512 bits", nameof(keySize));
        if (keySize % 2 != 0)
            throw new ArgumentException("Key size must be even", nameof(keySize));
        
        if (publicExponent == 0)
            publicExponent = DefaultPublicExponent;
        
        int primeSize = keySize / 2;
        RSAParameters key;
        int attempts = 0;
        const int maxAttempts = 100;
        
        do
        {
  
            BigInteger p = PrimeGenerator.GeneratePrime(primeSize);
            BigInteger q = PrimeGenerator.GeneratePrime(primeSize);
            
     
            while (p == q)
            {
                q = PrimeGenerator.GeneratePrime(primeSize);
            }

            BigInteger n = p * q;
            BigInteger phiN = (p - 1) * (q - 1);
            
            if (BigInteger.GreatestCommonDivisor(publicExponent, phiN) != 1)
                continue;
            BigInteger d = ModInverse(publicExponent, phiN);
            if (IsVulnerableToWienerAttack(n, publicExponent, d))
            {
                attempts++;
                if (attempts > maxAttempts)
                    throw new InvalidOperationException("Failed to generate secure key after maximum attempts");
                continue;
            }
            BigInteger dp = d % (p - 1);
            BigInteger dq = d % (q - 1);
            BigInteger qInv = ModInverse(q, p);
            
            key = new RSAParameters
            {
                Modulus = n,
                PublicExponent = publicExponent,
                PrivateExponent = d,
                PrimeP = p,
                PrimeQ = q,
                ExponentP = dp,
                ExponentQ = dq,
                Coefficient = qInv
            };
            
            break;
        } while (true);
        
        return key;
    }
    
    public bool IsVulnerableToWienerAttack(RSAParameters key)
    {
        if (key.PrivateExponent == null)
            return false;
        
        return IsVulnerableToWienerAttack(key.Modulus, key.PublicExponent, key.PrivateExponent.Value);
    }
    
    private bool IsVulnerableToWienerAttack(BigInteger n, BigInteger e, BigInteger d)
    {
        int bitLength = (int)n.GetBitLength();
        int quarterBitLength = bitLength / 4;
        BigInteger threshold = BigInteger.One << quarterBitLength;
        threshold = threshold / 3;
        return d < threshold;
    }
    
    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        if (BigInteger.GreatestCommonDivisor(a, m) != 1)
            throw new ArgumentException("Numbers must be coprime");
        
        BigInteger m0 = m;
        BigInteger y = 0, x = 1;
        
        if (m == 1)
            return 0;
        
        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;
            
            m = a % m;
            a = t;
            t = y;
            
            y = x - q * y;
            x = t;
        }
        
        if (x < 0)
            x += m0;
        
        return x;
    }
    
    private static BigInteger Sqrt(BigInteger n)
    {
        if (n == 0) return 0;
        if (n < 0) throw new ArgumentException("Cannot compute square root of negative number");
        BigInteger x = n;
        BigInteger y = (x + 1) / 2;
        
        while (y < x)
        {
            x = y;
            y = (x + n / x) / 2;
        }
        
        return x;
    }
}
