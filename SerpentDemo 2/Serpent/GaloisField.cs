namespace SerpentDemo.Serpent;

/// <summary>
/// Неприводимые полиномы над полем GF(2^8)
/// </summary>
public enum IrreduciblePolynomial
{
    /// <summary>
    /// x^8 + x^4 + x^3 + x^2 + 1 = 0x11D
    /// </summary>
    Polynomial_11D = 0x11D,
    
    /// <summary>
    /// x^8 + x^4 + x^3 + x + 1 = 0x11B (используется в AES)
    /// </summary>
    Polynomial_11B = 0x11B,
    
    /// <summary>
    /// x^8 + x^5 + x^3 + x + 1 = 0x12B
    /// </summary>
    Polynomial_12B = 0x12B,
    
    /// <summary>
    /// x^8 + x^5 + x^3 + x^2 + 1 = 0x12D
    /// </summary>
    Polynomial_12D = 0x12D,
    
    /// <summary>
    /// x^8 + x^6 + x^3 + x^2 + 1 = 0x14D
    /// </summary>
    Polynomial_14D = 0x14D,
    
    /// <summary>
    /// x^8 + x^6 + x^4 + x^3 + x + 1 = 0x15B
    /// </summary>
    Polynomial_15B = 0x15B,
    
    /// <summary>
    /// x^8 + x^6 + x^5 + x + 1 = 0x163
    /// </summary>
    Polynomial_163 = 0x163,
    
    /// <summary>
    /// x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1 = 0x1F5
    /// </summary>
    Polynomial_1F5 = 0x1F5
}

/// <summary>
/// Операции над полем Галуа GF(2^8)
/// </summary>
public static class GaloisField
{
    /// <summary>
    /// Умножение в поле GF(2^8)
    /// </summary>
    public static byte Multiply(byte a, byte b, IrreduciblePolynomial polynomial)
    {
        byte result = 0;
        byte temp = a;
        int poly = (int)polynomial;
        
        for (int i = 0; i < 8; i++)
        {
            if ((b & (1 << i)) != 0)
            {
                result ^= temp;
            }
            
            bool carry = (temp & 0x80) != 0;
            temp <<= 1;
            
            if (carry)
            {
                temp ^= (byte)(poly & 0xFF);
            }
        }
        
        return result;
    }
    
    /// <summary>
    /// Возведение в степень в поле GF(2^8)
    /// </summary>
    public static byte Power(byte a, int exponent, IrreduciblePolynomial polynomial)
    {
        if (exponent == 0) return 1;
        if (a == 0) return 0;
        
        byte result = 1;
        byte baseValue = a;
        
        while (exponent > 0)
        {
            if ((exponent & 1) != 0)
            {
                result = Multiply(result, baseValue, polynomial);
            }
            baseValue = Multiply(baseValue, baseValue, polynomial);
            exponent >>= 1;
        }
        
        return result;
    }
    
    /// <summary>
    /// Обратный элемент в поле GF(2^8)
    /// </summary>
    public static byte Inverse(byte a, IrreduciblePolynomial polynomial)
    {
        if (a == 0) return 0;
        
        // Используем расширенный алгоритм Евклида
        // Для GF(2^8) обратный элемент = a^(254)
        return Power(a, 254, polynomial);
    }
    
    /// <summary>
    /// Деление в поле GF(2^8)
    /// </summary>
    public static byte Divide(byte a, byte b, IrreduciblePolynomial polynomial)
    {
        if (b == 0) throw new DivideByZeroException();
        return Multiply(a, Inverse(b, polynomial), polynomial);
    }
}
