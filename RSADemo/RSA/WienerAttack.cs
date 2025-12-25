using System.Numerics;

namespace RSADemo.RSA;

public class WienerAttack : IWienerAttack
{
    public BigInteger? Attack(RSAParameters publicKey)
    {
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        
        BigInteger n = publicKey.Modulus;
        BigInteger e = publicKey.PublicExponent;
   
        if (!IsVulnerable(publicKey))
            return null;
        List<BigInteger> convergents = ComputeConvergents(e, n);
 
        foreach (var convergent in convergents)
        {
            BigInteger k = convergent;
            BigInteger d = (k * e - 1) / n;
            if (ValidatePrivateExponent(n, e, d))
            {
                return d;
            }
        }
        
        return null;
    }
    
    public bool IsVulnerable(RSAParameters publicKey)
    {
        if (publicKey == null)
            return false;
        
        BigInteger n = publicKey.Modulus;
        BigInteger e = publicKey.PublicExponent;

        BigInteger sqrtN = Sqrt(n);
        return e > n / 2;
    }
    private List<BigInteger> ComputeConvergents(BigInteger e, BigInteger n)
    {
        List<BigInteger> convergents = new List<BigInteger>();
        List<BigInteger> quotients = new List<BigInteger>();
        BigInteger a = e;
        BigInteger b = n;
        
        while (b != 0)
        {
            BigInteger q = a / b;
            quotients.Add(q);
            
            BigInteger temp = b;
            b = a % b;
            a = temp;
        }
        List<BigInteger> h = new List<BigInteger> { 0, 1 };
        List<BigInteger> k = new List<BigInteger> { 1, 0 };
        
        for (int i = 0; i < quotients.Count && i < 100; i++)
        {
            BigInteger q = quotients[i];
            BigInteger hNew = q * h[h.Count - 1] + h[h.Count - 2];
            BigInteger kNew = q * k[k.Count - 1] + k[k.Count - 2];
            
            h.Add(hNew);
            k.Add(kNew);

            if (kNew > 0)
            {
                convergents.Add(kNew);
            }
        }
        
        return convergents;
    }
    
    private bool ValidatePrivateExponent(BigInteger n, BigInteger e, BigInteger d)
    {

        BigInteger testMessage = 12345;
        if (testMessage >= n)
            testMessage = n / 2;
        
        try
        {
  
            BigInteger ciphertext = BigInteger.ModPow(testMessage, e, n);
            BigInteger decrypted = BigInteger.ModPow(ciphertext, d, n);
            return decrypted == testMessage;
        }
        catch
        {
            return false;
        }
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
