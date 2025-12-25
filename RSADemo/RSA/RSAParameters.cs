using System.Numerics;

namespace RSADemo.RSA;
public class RSAParameters
{
    public BigInteger Modulus { get; set; }
    public BigInteger PublicExponent { get; set; }
    public BigInteger? PrivateExponent { get; set; }
    public BigInteger? PrimeP { get; set; }
    public BigInteger? PrimeQ { get; set; }
    public BigInteger? ExponentP { get; set; }
    public BigInteger? ExponentQ { get; set; }
    public BigInteger? Coefficient { get; set; }
    public bool IsPublicOnly => PrivateExponent == null;
}
