namespace Converter;

public class SteamDataIntConverter : JsonConverter<int>
{
    public override int Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String && int.TryParse(reader.GetString(), out int value))
        {
            return value;
        }

        return 0; // 返回默认值或其他自定义逻辑
    }

    public override void Write(Utf8JsonWriter writer, int value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value);
    }
}
