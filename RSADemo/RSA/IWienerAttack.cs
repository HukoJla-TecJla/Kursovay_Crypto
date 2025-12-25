using System.Numerics;

namespace RSADemo.RSA;

public interface IWienerAttack
{
    BigInteger? Attack(RSAParameters publicKey);
    bool IsVulnerable(RSAParameters publicKey);
}
