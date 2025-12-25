using EncryptionCoursework.Core;
using EncryptionCoursework.Enums;

namespace EncryptionCoursework.Padding;


public static class PaddingProviderFactory
{
    public static IPaddingProvider Create(PaddingMode mode)
    {
        return mode switch
        {
            PaddingMode.Zeros => new ZerosPaddingProvider(),
            PaddingMode.AnsiX923 => new AnsiX923PaddingProvider(),
            PaddingMode.PKCS7 => new PKCS7PaddingProvider(),
            PaddingMode.ISO10126 => new ISO10126PaddingProvider(),
            _ => throw new ArgumentException($"Unknown padding mode: {mode}")
        };
    }
}
