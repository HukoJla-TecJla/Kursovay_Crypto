using System.Numerics;

namespace RSADemo.RSA;

public class RSAAlgorithm : IRSAAlgorithm
{
    public byte[] Encrypt(byte[] data, RSAParameters publicKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (publicKey.IsPublicOnly == false)
            throw new ArgumentException("Public key required for encryption");
        
        BigInteger message = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        
        if (message >= publicKey.Modulus)
            throw new ArgumentException("Message too large for key size");
   
        BigInteger ciphertext = BigInteger.ModPow(message, publicKey.PublicExponent, publicKey.Modulus);
        byte[] result = ciphertext.ToByteArray(isUnsigned: true, isBigEndian: true);
   
        int keySizeBytes = (int)((publicKey.Modulus.GetBitLength() + 7) / 8);
        if (result.Length < keySizeBytes)
        {
            byte[] padded = new byte[keySizeBytes];
            Array.Copy(result, 0, padded, keySizeBytes - result.Length, result.Length);
            return padded;
        }
        
        return result;
    }
    
    public byte[] Decrypt(byte[] data, RSAParameters privateKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.PrivateExponent == null)
            throw new ArgumentException("Private key required for decryption");
        
        BigInteger ciphertext = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        
        if (ciphertext >= privateKey.Modulus)
            throw new ArgumentException("Ciphertext too large for key size");
        
        BigInteger message;

        if (privateKey.PrimeP != null && privateKey.PrimeQ != null &&
            privateKey.ExponentP != null && privateKey.ExponentQ != null &&
            privateKey.Coefficient != null)
        {

            BigInteger mp = BigInteger.ModPow(ciphertext, privateKey.ExponentP.Value, privateKey.PrimeP.Value);
            BigInteger mq = BigInteger.ModPow(ciphertext, privateKey.ExponentQ.Value, privateKey.PrimeQ.Value);
            
            BigInteger h = (privateKey.Coefficient.Value * (mp - mq)) % privateKey.PrimeP.Value;
            if (h < 0) h += privateKey.PrimeP.Value;
            message = mq + privateKey.PrimeQ.Value * h;
        }
        else
        {
            message = BigInteger.ModPow(ciphertext, privateKey.PrivateExponent.Value, privateKey.Modulus);
        }
        
     
        byte[] result = message.ToByteArray(isUnsigned: true, isBigEndian: true);
        

        int startIndex = 0;
        while (startIndex < result.Length && result[startIndex] == 0)
            startIndex++;
        
        if (startIndex > 0)
        {
            byte[] trimmed = new byte[result.Length - startIndex];
            Array.Copy(result, startIndex, trimmed, 0, trimmed.Length);
            return trimmed;
        }
        
        return result;
    }
    
    public int GetMaxBlockSize(RSAParameters key)
    {
        int keySizeBytes = (int)((key.Modulus.GetBitLength() + 7) / 8);
        return keySizeBytes - 11;
    }
}
