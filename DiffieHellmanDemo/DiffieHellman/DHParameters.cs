using System.Numerics;

namespace DiffieHellmanDemo.DiffieHellman;

public class DHParameters
{
    public BigInteger Prime { get; set; }
    public BigInteger Generator { get; set; }
    public int KeySize { get; set; }
}

public class DHParticipant
{
    public BigInteger PrivateKey { get; set; }
    public BigInteger PublicKey { get; set; }
    public BigInteger? SharedSecret { get; set; }
    public string Name { get; set; } = "";
}
