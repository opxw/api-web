// Copyright (c) 2026 - opx
using Microsoft.Extensions.Options;

namespace Opx.Api.Web.WebSockets;

internal sealed class OpxWebSocketMessageRouter
{
	private readonly IOpxWebSocketConnectionManager _connections;
	private readonly IReadOnlyDictionary<string, IOpxWebSocketMessageHandler> _handlers;
	private readonly IOptionsMonitor<OpxWebSocketOptions> _options;

	public OpxWebSocketMessageRouter(
		IOpxWebSocketConnectionManager connections,
		IEnumerable<IOpxWebSocketMessageHandler> handlers,
		IOptionsMonitor<OpxWebSocketOptions> options)
	{
		_connections = connections;
		_options = options;
		_handlers = handlers.ToDictionary(handler => handler.Type, StringComparer.OrdinalIgnoreCase);
	}

	public async ValueTask<bool> TryRouteAsync(OpxWebSocketSession session, ReadOnlyMemory<byte> utf8Message, CancellationToken cancellationToken)
	{
		var options = _options.CurrentValue;
		if (!options.EnableTypedRouting || !OpxWebSocketProtocol.TryDeserialize(utf8Message.Span, out var message) || message is null)
		{
			return false;
		}

		var succeeded = message.Type.ToLowerInvariant() switch
		{
			"opx.subscribe" => await SubscribeAsync(session, message, options, cancellationToken),
			"opx.unsubscribe" => await UnsubscribeAsync(session, message, cancellationToken),
			"opx.ping" => await PongAsync(session, message, cancellationToken),
			"opx.ack" or "opx.pong" => true,
			_ => await DispatchAsync(session, message, cancellationToken)
		};

		if (options.EnableAcknowledgements
			&& message.RequireAck
			&& !string.IsNullOrWhiteSpace(message.MessageId)
			&& !message.Type.Equals("opx.ack", StringComparison.OrdinalIgnoreCase))
		{
			await session.SendMessageAsync("opx.ack", new { accepted = succeeded }, correlationId: message.MessageId, cancellationToken: cancellationToken);
		}

		return true;
	}

	private async ValueTask<bool> SubscribeAsync(OpxWebSocketSession session, OpxWebSocketMessage message, OpxWebSocketOptions options, CancellationToken cancellationToken)
	{
		var topic = ResolveTopic(message);
		if (!IsValidTopic(topic, options.MaxTopicLength)
			|| (!session.Topics.Contains(topic!, StringComparer.OrdinalIgnoreCase)
				&& session.TopicCount >= Math.Max(1, options.MaxSubscriptionsPerConnection)))
		{
			await SendErrorAsync(session, message, "Invalid topic or subscription limit exceeded", cancellationToken);
			return false;
		}

		var added = await _connections.AddToTopicAsync(session.Id, topic!, cancellationToken);
		await session.SendMessageAsync("opx.subscribed", new { topic, added }, topic, correlationId: message.MessageId, cancellationToken: cancellationToken);
		return true;
	}

	private async ValueTask<bool> UnsubscribeAsync(OpxWebSocketSession session, OpxWebSocketMessage message, CancellationToken cancellationToken)
	{
		var topic = ResolveTopic(message);
		if (string.IsNullOrWhiteSpace(topic))
		{
			await SendErrorAsync(session, message, "Topic is required", cancellationToken);
			return false;
		}

		var removed = await _connections.RemoveFromTopicAsync(session.Id, topic, cancellationToken);
		await session.SendMessageAsync("opx.unsubscribed", new { topic, removed }, topic, correlationId: message.MessageId, cancellationToken: cancellationToken);
		return true;
	}

	private static async ValueTask<bool> PongAsync(OpxWebSocketSession session, OpxWebSocketMessage message, CancellationToken cancellationToken)
	{
		await session.SendMessageAsync("opx.pong", new { timestamp = DateTimeOffset.UtcNow }, correlationId: message.MessageId, cancellationToken: cancellationToken);
		return true;
	}

	private async ValueTask<bool> DispatchAsync(OpxWebSocketSession session, OpxWebSocketMessage message, CancellationToken cancellationToken)
	{
		if (!_handlers.TryGetValue(message.Type, out var handler))
		{
			await SendErrorAsync(session, message, $"No handler registered for '{message.Type}'", cancellationToken);
			return false;
		}

		await handler.HandleAsync(session, message, cancellationToken);
		return true;
	}

	private static Task SendErrorAsync(OpxWebSocketSession session, OpxWebSocketMessage message, string error, CancellationToken cancellationToken)
	{
		return session.SendMessageAsync("opx.error", new { error }, correlationId: message.MessageId, cancellationToken: cancellationToken);
	}

	private static string? ResolveTopic(OpxWebSocketMessage message)
	{
		if (!string.IsNullOrWhiteSpace(message.Topic))
		{
			return message.Topic.Trim();
		}

		if (message.Data.ValueKind == System.Text.Json.JsonValueKind.Object
			&& message.Data.TryGetProperty("topic", out var topic))
		{
			return topic.GetString()?.Trim();
		}

		return null;
	}

	private static bool IsValidTopic(string? topic, int maxLength)
	{
		if (string.IsNullOrWhiteSpace(topic) || topic.Length > Math.Max(1, maxLength))
		{
			return false;
		}

		return topic.All(character => char.IsLetterOrDigit(character) || character is ':' or '.' or '_' or '-' or '/');
	}
}
