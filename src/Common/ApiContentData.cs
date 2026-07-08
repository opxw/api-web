using System.Text.Json.Serialization;

namespace Opx.Api.Web.Common;

[Serializable]
public sealed class ApiContentData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "file";

    [JsonPropertyName("contentType")]
    public string ContentType { get; set; } = "application/octet-stream";

    [JsonPropertyName("fileName")]
    public string? FileName { get; set; }

    [JsonPropertyName("length")]
    public long Length { get; set; }

    [JsonPropertyName("encoding")]
    public string Encoding { get; set; } = "base64";

    [JsonPropertyName("rawData")]
    public byte[] RawData { get; set; } = [];

    public static ApiContentData FromBytes(
        byte[] rawData,
        string contentType,
        string? fileName = null,
        string type = "file")
    {
        return new ApiContentData
        {
            Type = string.IsNullOrWhiteSpace(type) ? "file" : type,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
            FileName = fileName,
            Length = rawData.LongLength,
            RawData = rawData
        };
    }
}
