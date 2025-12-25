namespace SerpentDemo.Padding;

/// <summary>
/// Интерфейс для провайдеров набивки
/// </summary>
public interface IPaddingProvider
{
    /// <summary>
    /// Добавить набивку к данным
    /// </summary>
    byte[] AddPadding(byte[] data, int blockSize);
    
    /// <summary>
    /// Удалить набивку из данных
    /// </summary>
    byte[] RemovePadding(byte[] data, int blockSize);
}