using System.Numerics;

namespace DiffieHellmanDemo.DiffieHellman;


public interface IDiffieHellman
{
    DHParameters GenerateParameters(int keySize);
    DHParticipant CreateParticipant(DHParameters parameters, string name);
    BigInteger ComputeSharedSecret(DHParticipant participant, BigInteger otherPublicKey, DHParameters parameters);
}
