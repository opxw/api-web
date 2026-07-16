// Copyright (c) 2026 - opx
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.WebSockets;

public interface IOpxWebSocketConnectionManager
{
	int Count { get; }
	bool TryGet(string sessionId, out OpxWebSocketSession? session);
	Task<bool> AddToTopicAsync(string sessionId, string topic, CancellationToken cancellationToken = default);
	Task<bool> RemoveFromTopicAsync(string sessionId, string topic, CancellationToken cancellationToken = default);
	Task<bool> AddToGroupAsync(string sessionId, string group, CancellationToken cancellationToken = default);
	Task<bool> RemoveFromGroupAsync(string sessionId, string group, CancellationToken cancellationToken = default);
	Task SendToSessionAsync<T>(string sessionId, string type, T data, CancellationToken cancellationToken = default);
	Task SendToUserAsync<T>(string userId, string type, T data, CancellationToken cancellationToken = default);
	Task SendToTopicAsync<T>(string topic, string type, T data, CancellationToken cancellationToken = default);
	Task SendToGroupAsync<T>(string group, string type, T data, CancellationToken cancellationToken = default);
	Task BroadcastMessageAsync<T>(string type, T data, CancellationToken cancellationToken = default);
	Task BroadcastTextAsync(string message, CancellationToken cancellationToken = default);
	Task BroadcastJsonAsync<T>(T message, CancellationToken cancellationToken = default);
	OpxWebSocketHealthSnapshot GetHealth();
}

internal sealed class OpxWebSocketConnectionManager : IOpxWebSocketConnectionManager
{
	private readonly IOpxWebSocketBackplane _backplane;
	private readonly string _instanceId = Guid.NewGuid().ToString("N");
	private readonly OpxProtectionMetrics _metrics;
	private readonly ConcurrentDictionary<string, OpxWebSocketSession> _sessions = new(StringComparer.Ordinal);
	private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _topics = new(StringComparer.OrdinalIgnoreCase);
	private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _users = new(StringComparer.OrdinalIgnoreCase);

	public OpxWebSocketConnectionManager(IOpxWebSocketBackplane backplane, OpxProtectionMetrics metrics)
	{
		_backplane = backplane;
		_metrics = metrics;
		_backplane.SetReceiver(ReceiveBackplaneAsync);
	}

	public int Count => _sessions.Count;

	public bool TryGet(string sessionId, out OpxWebSocketSession? session) => _sessions.TryGetValue(sessionId, out session);

	public Task<bool> AddToTopicAsync(string sessionId, string topic, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (!_sessions.TryGetValue(sessionId, out var session) || string.IsNullOrWhiteSpace(topic))
		{
			return Task.FromResult(false);
		}

		var members = _topics.GetOrAdd(topic, _ => new ConcurrentDictionary<string, byte>(StringComparer.Ordinal));
		var added = members.TryAdd(sessionId, 0);
		if (added)
		{
			session.TryAddTopic(topic);
		}
		return Task.FromResult(added);
	}

	public Task<bool> RemoveFromTopicAsync(string sessionId, string topic, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (!_topics.TryGetValue(topic, out var members))
		{
			return Task.FromResult(false);
		}

		var removed = members.TryRemove(sessionId, out _);
		if (removed && _sessions.TryGetValue(sessionId, out var session))
		{
			session.TryRemoveTopic(topic);
		}
		if (members.IsEmpty)
		{
			_topics.TryRemove(new KeyValuePair<string, ConcurrentDictionary<string, byte>>(topic, members));
		}

		return Task.FromResult(removed);
	}

	public Task<bool> AddToGroupAsync(string sessionId, string group, CancellationToken cancellationToken = default) => AddToTopicAsync(sessionId, group, cancellationToken);
	public Task<bool> RemoveFromGroupAsync(string sessionId, string group, CancellationToken cancellationToken = default) => RemoveFromTopicAsync(sessionId, group, cancellationToken);

	public Task SendToSessionAsync<T>(string sessionId, string type, T data, CancellationToken cancellationToken = default)
		=> SendEnvelopeAsync("session", sessionId, type, data, null, cancellationToken);

	public Task SendToUserAsync<T>(string userId, string type, T data, CancellationToken cancellationToken = default)
		=> SendEnvelopeAsync("user", userId, type, data, null, cancellationToken);

	public Task SendToTopicAsync<T>(string topic, string type, T data, CancellationToken cancellationToken = default)
		=> SendEnvelopeAsync("topic", topic, type, data, topic, cancellationToken);

	public Task SendToGroupAsync<T>(string group, string type, T data, CancellationToken cancellationToken = default)
		=> SendToTopicAsync(group, type, data, cancellationToken);

	public Task BroadcastMessageAsync<T>(string type, T data, CancellationToken cancellationToken = default)
		=> SendEnvelopeAsync("broadcast", null, type, data, null, cancellationToken);

	public Task BroadcastTextAsync(string message, CancellationToken cancellationToken = default)
		=> SendPayloadAsync("broadcast", null, message, true, cancellationToken);

	public Task BroadcastJsonAsync<T>(T message, CancellationToken cancellationToken = default)
		=> SendPayloadAsync("broadcast", null, JsonSerializer.Serialize(message, OpxWebSocketProtocol.JsonOptions), true, cancellationToken);

	public OpxWebSocketHealthSnapshot GetHealth()
		=> new(Count, _users.Count, _topics.Count, _backplane.Enabled, _backplane.IsConnected, DateTimeOffset.UtcNow);

	internal bool TryAdd(OpxWebSocketSession session)
	{
		if (!_sessions.TryAdd(session.Id, session))
		{
			return false;
		}

		if (!string.IsNullOrWhiteSpace(session.UserId))
		{
			_users.GetOrAdd(session.UserId, _ => new ConcurrentDictionary<string, byte>(StringComparer.Ordinal)).TryAdd(session.Id, 0);
		}

		_metrics.IncrementWebSocketConnected();
		return true;
	}

	internal bool TryRemove(string sessionId, out OpxWebSocketSession? session)
	{
		if (!_sessions.TryRemove(sessionId, out session))
		{
			return false;
		}

		foreach (var topic in _topics)
		{
			RemoveMember(_topics, topic.Key, topic.Value, sessionId);
		}

		if (!string.IsNullOrWhiteSpace(session.UserId) && _users.TryGetValue(session.UserId, out var userSessions))
		{
			RemoveMember(_users, session.UserId, userSessions, sessionId);
		}

		_metrics.IncrementWebSocketDisconnected();
		return true;
	}

	internal async Task CloseAllAsync(CancellationToken cancellationToken)
	{
		await Task.WhenAll(_sessions.Values.Select(session => CloseSafelyAsync(session, cancellationToken)));
	}

	private async Task SendEnvelopeAsync<T>(string target, string? key, string type, T data, string? topic, CancellationToken cancellationToken)
	{
		var payload = Encoding.UTF8.GetString(OpxWebSocketProtocol.Serialize(type, data, topic));
		await SendPayloadAsync(target, key, payload, true, cancellationToken);
	}

	private async Task SendPayloadAsync(string target, string? key, string payload, bool publish, CancellationToken cancellationToken)
	{
		await SendLocalAsync(target, key, payload, cancellationToken);
		if (publish && _backplane.Enabled)
		{
			await _backplane.PublishAsync(new OpxWebSocketBackplaneMessage(_instanceId, target, key, payload), cancellationToken);
		}
	}

	private ValueTask ReceiveBackplaneAsync(OpxWebSocketBackplaneMessage message, CancellationToken cancellationToken)
	{
		return message.Origin == _instanceId
			? ValueTask.CompletedTask
			: new ValueTask(SendLocalAsync(message.Target, message.Key, message.Payload, cancellationToken));
	}

	private Task SendLocalAsync(string target, string? key, string payload, CancellationToken cancellationToken)
	{
		IEnumerable<OpxWebSocketSession> sessions = target switch
		{
			"session" when key is not null && _sessions.TryGetValue(key, out var session) => [session],
			"user" when key is not null && _users.TryGetValue(key, out var userSessions) => ResolveSessions(userSessions.Keys),
			"topic" when key is not null && _topics.TryGetValue(key, out var topicSessions) => ResolveSessions(topicSessions.Keys),
			"broadcast" => _sessions.Values,
			_ => []
		};

		return SendManyAsync(sessions, payload, cancellationToken);
	}

	private IEnumerable<OpxWebSocketSession> ResolveSessions(IEnumerable<string> sessionIds)
	{
		foreach (var sessionId in sessionIds)
		{
			if (_sessions.TryGetValue(sessionId, out var session))
			{
				yield return session;
			}
		}
	}

	private static async Task SendManyAsync(IEnumerable<OpxWebSocketSession> sessions, string payload, CancellationToken cancellationToken)
	{
		await Task.WhenAll(sessions.Select(async session =>
		{
			if (session.State != WebSocketState.Open)
			{
				return;
			}

			try
			{
				await session.SendTextAsync(payload, cancellationToken);
			}
			catch (WebSocketException)
			{
				// A disconnect racing with delivery is expected.
			}
		}));
	}

	private static void RemoveMember(
		ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> index,
		string key,
		ConcurrentDictionary<string, byte> members,
		string sessionId)
	{
		members.TryRemove(sessionId, out _);
		if (members.IsEmpty)
		{
			index.TryRemove(new KeyValuePair<string, ConcurrentDictionary<string, byte>>(key, members));
		}
	}

	private static async Task CloseSafelyAsync(OpxWebSocketSession session, CancellationToken cancellationToken)
	{
		try
		{
			await session.CloseAsync(WebSocketCloseStatus.EndpointUnavailable, "Server shutting down", cancellationToken);
		}
		catch (Exception exception) when (exception is WebSocketException or OperationCanceledException)
		{
		}
	}
}
