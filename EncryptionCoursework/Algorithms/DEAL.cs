using EncryptionCoursework.Core;

namespace EncryptionCoursework.Algorithms;


public sealed class DEAL : IBlockCipher
{
    public int BlockSize => 16; 
    public int KeySize => 16;   

    private readonly DES _des = new();

    private const int Rounds = 6;

    public byte[] EncryptBlock(byte[] block, byte[] key)
    {
        if (block == null || block.Length != 16)
            throw new ArgumentException("Block must be 16 bytes");
        if (!IsValidKeySize(key))
            throw new ArgumentException("Key must be 16 bytes");

        var roundKeys = GenerateRoundKeys(key);

        byte[] L = block[..8];
        byte[] R = block[8..];

        for (int i = 0; i < Rounds; i++)
        {
            byte[] f = _des.EncryptBlock(R, roundKeys[i]);

            byte[] newR = new byte[8];
            for (int j = 0; j < 8; j++)
                newR[j] = (byte)(L[j] ^ f[j]);

            L = R;
            R = newR;
        }

      
        byte[] result = new byte[16];
        Array.Copy(R, 0, result, 0, 8);
        Array.Copy(L, 0, result, 8, 8);

        return result;
    }

    public byte[] DecryptBlock(byte[] block, byte[] key)
    {
        if (block == null || block.Length != 16)
            throw new ArgumentException("Block must be 16 bytes");
        if (!IsValidKeySize(key))
            throw new ArgumentException("Key must be 16 bytes");

        var roundKeys = GenerateRoundKeys(key);

       
        byte[] R = block[..8];
        byte[] L = block[8..];

        for (int i = Rounds - 1; i >= 0; i--)
        {
            byte[] f = _des.EncryptBlock(L, roundKeys[i]);

            byte[] newL = new byte[8];
            for (int j = 0; j < 8; j++)
                newL[j] = (byte)(R[j] ^ f[j]);

            R = L;
            L = newL;
        }

        byte[] result = new byte[16];
        Array.Copy(L, 0, result, 0, 8);
        Array.Copy(R, 0, result, 8, 8);

        return result;
    }

    private byte[][] GenerateRoundKeys(byte[] key)
    {
        byte[][] rk = new byte[Rounds][];

        byte[] kL = key[..8];
        byte[] kR = key[8..];

        rk[0] = kL;
        rk[1] = kR;
        rk[2] = _des.EncryptBlock(kL, kR);
        rk[3] = _des.EncryptBlock(kR, kL);
        rk[4] = _des.EncryptBlock(rk[0], rk[2]);
        rk[5] = _des.EncryptBlock(rk[1], rk[3]);

        return rk;
    }

    public bool IsValidKeySize(byte[] key) => key?.Length == 16;
}