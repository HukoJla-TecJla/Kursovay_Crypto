using SerpentDemo.Enums;
using System;

namespace SerpentDemo.Serpent;

public sealed class SerpentCipher : ISerpentCipher
{
    public int BlockSize => 16;
    public int KeySize => 32;

    private const int ROUNDS = 32;
    private const uint PHI = 0x9E3779B9;

    

    public byte[] EncryptBlock(byte[] input, byte[] key, IrreduciblePolynomial _)
    {
        uint[] x = BytesToWords(input);
        uint[] rk = MakeRoundKeys(key);

        for (int r = 0; r < 31; r++)
        {
            Xor(x, rk, r * 4);
            ApplySBox(x, r % 8);
            LT(x);
        }

        Xor(x, rk, 31 * 4);
        ApplySBox(x, 31 % 8);
        Xor(x, rk, 32 * 4);

        return WordsToBytes(x);
    }

    public byte[] DecryptBlock(byte[] input, byte[] key, IrreduciblePolynomial _)
    {
        uint[] x = BytesToWords(input);
        uint[] rk = MakeRoundKeys(key);

        Xor(x, rk, 32 * 4);
        ApplyInvSBox(x, 31 % 8);
        Xor(x, rk, 31 * 4);

        for (int r = 30; r >= 0; r--)
        {
            InvLT(x);
            ApplyInvSBox(x, r % 8);
            Xor(x, rk, r * 4);
        }

        return WordsToBytes(x);
    }

    public bool IsValidKeySize(byte[] key)
        => key is { Length: 16 or 24 or 32 };
    

    private static readonly byte[][] SBox =
    {
        new byte[] { 3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12 },
        new byte[] { 15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4 },
        new byte[] { 8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2 },
        new byte[] { 0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14 },
        new byte[] { 1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13 },
        new byte[] { 15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1 },
        new byte[] { 7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0 },
        new byte[] { 1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6 }
    };

    private static readonly byte[][] InvSBox =
    {
        Invert(SBox[0]), Invert(SBox[1]), Invert(SBox[2]), Invert(SBox[3]),
        Invert(SBox[4]), Invert(SBox[5]), Invert(SBox[6]), Invert(SBox[7])
    };

    private static void ApplySBox(uint[] x, int box)
    {
        for (int i = 0; i < 4; i++)
        {
            uint w = x[i];
            uint r = 0;

            for (int p = 0; p < 8; p++)
            {
                int n = (int)((w >> (p * 4)) & 0xF);
                r |= (uint)SBox[box][n] << (p * 4);
            }

            x[i] = r;
        }
    }

    private static void ApplyInvSBox(uint[] x, int box)
    {
        for (int i = 0; i < 4; i++)
        {
            uint w = x[i];
            uint r = 0;

            for (int p = 0; p < 8; p++)
            {
                int n = (int)((w >> (p * 4)) & 0xF);
                r |= (uint)InvSBox[box][n] << (p * 4);
            }

            x[i] = r;
        }
    }

    private static byte[] Invert(byte[] s)
    {
        byte[] inv = new byte[16];
        for (int i = 0; i < 16; i++)
            inv[s[i]] = (byte)i;
        return inv;
    }



    private static void LT(uint[] x)
    {
        x[0] = RotL(x[0], 13);
        x[2] = RotL(x[2], 3);
        x[1] ^= x[0] ^ x[2];
        x[3] ^= x[2] ^ (x[0] << 3);
        x[1] = RotL(x[1], 1);
        x[3] = RotL(x[3], 7);
        x[0] ^= x[1] ^ x[3];
        x[2] ^= x[3] ^ (x[1] << 7);
        x[0] = RotL(x[0], 5);
        x[2] = RotL(x[2], 22);
    }

    private static void InvLT(uint[] x)
    {
        x[2] = RotR(x[2], 22);
        x[0] = RotR(x[0], 5);
        x[2] ^= x[3] ^ (x[1] << 7);
        x[0] ^= x[1] ^ x[3];
        x[3] = RotR(x[3], 7);
        x[1] = RotR(x[1], 1);
        x[3] ^= x[2] ^ (x[0] << 3);
        x[1] ^= x[0] ^ x[2];
        x[2] = RotR(x[2], 3);
        x[0] = RotR(x[0], 13);
    }

    

    private static uint[] MakeRoundKeys(byte[] key)
    {
        uint[] w = new uint[140];
        byte[] k = new byte[32];
        Array.Copy(key, k, key.Length);
        if (key.Length < 32)
            k[key.Length] = 1;

        for (int i = 0; i < 8; i++)
        {
            w[i] =
                ((uint)k[i * 4 + 0]) |
                ((uint)k[i * 4 + 1] << 8) |
                ((uint)k[i * 4 + 2] << 16) |
                ((uint)k[i * 4 + 3] << 24);
        }

        for (int i = 8; i < 140; i++)
            w[i] = RotL(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (uint)(i - 8), 11);

        uint[] rk = new uint[132];
        Array.Copy(w, 8, rk, 0, 132);

        for (int r = 0; r < 33; r++)
        {
            uint[] temp = new uint[4];
            Array.Copy(rk, r * 4, temp, 0, 4);

            ApplySBox(temp, (35 - r) % 8);

            Array.Copy(temp, 0, rk, r * 4, 4);
        }

        return rk;
    }

    

    private static void Xor(uint[] x, uint[] k, int o)
    {
        for (int i = 0; i < 4; i++)
            x[i] ^= k[o + i];
    }

    private static uint RotL(uint x, int n) => (x << n) | (x >> (32 - n));
    private static uint RotR(uint x, int n) => (x >> n) | (x << (32 - n));

    private static uint[] BytesToWords(byte[] b)
    {
        uint[] w = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            w[i] =
                ((uint)b[i * 4 + 0]) |
                ((uint)b[i * 4 + 1] << 8) |
                ((uint)b[i * 4 + 2] << 16) |
                ((uint)b[i * 4 + 3] << 24);
        }
        return w;
    }

    private static byte[] WordsToBytes(uint[] w)
    {
        byte[] b = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            b[i * 4 + 0] = (byte)(w[i]);
            b[i * 4 + 1] = (byte)(w[i] >> 8);
            b[i * 4 + 2] = (byte)(w[i] >> 16);
            b[i * 4 + 3] = (byte)(w[i] >> 24);
        }
        return b;
    }
}