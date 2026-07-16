// Copyright (c) 2026 - opx
using System.Text.Json;

namespace Opx.Api.Web.WebSockets;

public sealed class OpxWebSocketMessage
{
	public string Type { get; set; } = string.Empty;
	public string MessageId { get; set; } = string.Empty;
	public string? CorrelationId { get; set; }
	public string? Topic { get; set; }
	public bool RequireAck { get; set; }
	public JsonElement Data { get; set; }

	public T? GetData<T>(JsonSerializerOptions? options = null)
	{
		return Data.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
			? default
			: Data.Deserialize<T>(options);
	}
}

internal static class OpxWebSocketProtocol
{
	public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

	public static byte[] Serialize<T>(string type, T data, string? topic = null, string? messageId = null, string? correlationId = null, bool requireAck = false)
	{
		return JsonSerializer.SerializeToUtf8Bytes(new
		{
			type,
			messageId = messageId ?? Guid.NewGuid().ToString("N"),
			correlationId,
			topic,
			requireAck,
			data
		}, JsonOptions);
	}

	public static bool TryDeserialize(ReadOnlySpan<byte> utf8Message, out OpxWebSocketMessage? message)
	{
		try
		{
			message = JsonSerializer.Deserialize<OpxWebSocketMessage>(utf8Message, JsonOptions);
			return message is not null && !string.IsNullOrWhiteSpace(message.Type);
		}
		catch (JsonException)
		{
			message = null;
			return false;
		}
	}
}
