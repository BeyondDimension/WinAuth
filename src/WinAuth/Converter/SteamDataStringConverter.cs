namespace Converter;

public class SteamDataStringConverter : JsonConverter<string>
{
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number && typeToConvert == typeof(string) && reader.TryGetDecimal(out var value))
        {
            return value.ToString();
        }

        return string.Empty; // 返回默认值或其他自定义逻辑
    }

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value);
    }
}
