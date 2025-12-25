using System.Numerics;

namespace DiffieHellmanDemo.DiffieHellman;

public class DiffieHellmanProtocol : IDiffieHellman
{
    private static readonly Random _random = new();
    
    public DHParameters GenerateParameters(int keySize)
    {
        if (keySize < 256)
            throw new ArgumentException("Key size must be at least 256 bits", nameof(keySize));
      
        BigInteger p = PrimeGenerator.GenerateSafePrime(keySize);
        
        BigInteger g = FindGenerator(p);
        
        return new DHParameters
        {
            Prime = p,
            Generator = g,
            KeySize = keySize
        };
    }
    
    public DHParticipant CreateParticipant(DHParameters parameters, string name)
    {
      
        BigInteger privateKey = GeneratePrivateKey(parameters.Prime);
        BigInteger publicKey = BigInteger.ModPow(parameters.Generator, privateKey, parameters.Prime);
        
        return new DHParticipant
        {
            PrivateKey = privateKey,
            PublicKey = publicKey,
            Name = name
        };
    }
    
    public BigInteger ComputeSharedSecret(
        DHParticipant participant,
        BigInteger otherPublicKey,
        DHParameters parameters)
    {
        BigInteger sharedSecret = BigInteger.ModPow(otherPublicKey, participant.PrivateKey, parameters.Prime);
        
        participant.SharedSecret = sharedSecret;
        
        return sharedSecret;
    }
    
    private static BigInteger FindGenerator(BigInteger p)
    {
        BigInteger[] candidates = { 2, 3, 5, 7, 11 };
        
        foreach (BigInteger candidate in candidates)
        {
            if (IsGenerator(candidate, p))
                return candidate;
        }
        
        for (BigInteger g = 2; g < p; g++)
        {
            if (IsGenerator(g, p))
                return g;
            
            if (g > 1000)
                break;
        }
        
        return 2;
    }
    
    private static bool IsGenerator(BigInteger g, BigInteger p)
    {
        BigInteger phi = p - 1;
        BigInteger q = phi / 2;
        
        if (BigInteger.ModPow(g, 2, p) == 1)
            return false;
        
        if (BigInteger.ModPow(g, q, p) == 1)
            return false;
        
        return true;
    }
    private static BigInteger GeneratePrivateKey(BigInteger p)
    {
        BigInteger max = p - 2;
        BigInteger min = 2;
        BigInteger range = max - min + 1;
        int byteCount = range.GetByteCount();
        byte[] bytes = new byte[byteCount];
        Random.Shared.NextBytes(bytes);
        
        BigInteger randomValue = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        randomValue %= range;
        randomValue += min;
        
        return randomValue;
    }
}
