using SerpentDemo.Enums;

namespace SerpentDemo.CipherModes;

public static class CipherModeFactory
{
    public static ICipherMode Create(CipherMode mode)
    {
        return mode switch
        {
            CipherMode.ECB => new ECBMode(),
            CipherMode.CBC => new CBCMode(),
            CipherMode.PCBC => new PCBCMode(),
            CipherMode.CFB => new CFBMode(),
            CipherMode.OFB => new OFBMode(),
            CipherMode.CTR => new CTRMode(),
            CipherMode.RandomDelta => new RandomDeltaMode(),
            _ => throw new ArgumentException($"Unknown cipher mode: {mode}")
        };
    }
}
