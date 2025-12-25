using System.Numerics;

namespace RSADemo.RSA;

public interface IRSAKeyGenerator
{
    RSAParameters GenerateKeyPair(int keySize, BigInteger publicExponent);
    bool IsVulnerableToWienerAttack(RSAParameters key);
}
