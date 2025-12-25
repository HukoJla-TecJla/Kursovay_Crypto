namespace RSADemo.RSA;


public interface IRSAAlgorithm
{
    byte[] Encrypt(byte[] data, RSAParameters publicKey);
    byte[] Decrypt(byte[] data, RSAParameters privateKey);
    int GetMaxBlockSize(RSAParameters key);
}
