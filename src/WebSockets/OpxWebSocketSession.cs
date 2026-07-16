// Copyright (c) 2026 - opx
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Security.Claims;
using Opx.Api.Web.Protection;
using System.Collections.Concurrent;

namespace Opx.Api.Web.WebSockets;

public sealed class OpxWebSocketSession : IAsyncDisposable
{
	private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
	private readonly SemaphoreSlim _sendLock = new(1, 1);
	private readonly OpxProtectionMetrics? _metrics;
	private readonly ConcurrentDictionary<string, byte> _topics = new(StringComparer.OrdinalIgnoreCase);
	private long _lastReceivedUnixMilliseconds;
	private long _lastSentUnixMilliseconds;
	private int _disposed;

	internal OpxWebSocketSession(string id, WebSocket socket, HttpContext httpContext, OpxProtectionMetrics? metrics = null)
	{
		Id = id;
		Socket = socket;
		HttpContext = httpContext;
		ConnectedAt = DateTimeOffset.UtcNow;
		UserId = ResolveUserId(httpContext.User);
		_metrics = metrics;
		_lastReceivedUnixMilliseconds = ConnectedAt.ToUnixTimeMilliseconds();
		_lastSentUnixMilliseconds = _lastReceivedUnixMilliseconds;
	}

	public string Id { get; }
	public DateTimeOffset ConnectedAt { get; }
	public HttpContext HttpContext { get; }
	public string? UserId { get; }
	public DateTimeOffset LastReceivedAt => DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _lastReceivedUnixMilliseconds));
	public DateTimeOffset LastSentAt => DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _lastSentUnixMilliseconds));
	public WebSocketState State => Socket.State;
	public IReadOnlyCollection<string> Topics => _topics.Keys.ToArray();
	public int TopicCount => _topics.Count;
	internal WebSocket Socket { get; }

	public Task SendTextAsync(string message, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(message);
		return SendAsync(Encoding.UTF8.GetBytes(message), WebSocketMessageType.Text, cancellationToken);
	}

	public Task SendJsonAsync<T>(T message, CancellationToken cancellationToken = default)
	{
		return SendAsync(JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions), WebSocketMessageType.Text, cancellationToken);
	}

	public Task SendBinaryAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
	{
		return SendAsync(message, WebSocketMessageType.Binary, cancellationToken);
	}

	public Task SendMessageAsync<T>(
		string type,
		T data,
		string? topic = null,
		string? messageId = null,
		string? correlationId = null,
		bool requireAck = false,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(type))
		{
			throw new ArgumentException("Message type is required.", nameof(type));
		}

		return SendAsync(OpxWebSocketProtocol.Serialize(type, data, topic, messageId, correlationId, requireAck), WebSocketMessageType.Text, cancellationToken);
	}

	internal void MarkReceived(int bytes)
	{
		Interlocked.Exchange(ref _lastReceivedUnixMilliseconds, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
		_metrics?.RecordWebSocketMessageReceived(bytes);
	}

	internal bool TryAddTopic(string topic) => _topics.TryAdd(topic, 0);
	internal bool TryRemoveTopic(string topic) => _topics.TryRemove(topic, out _);

	public async Task CloseAsync(
		WebSocketCloseStatus status = WebSocketCloseStatus.NormalClosure,
		string? description = null,
		CancellationToken cancellationToken = default)
	{
		if (Socket.State is not (WebSocketState.Open or WebSocketState.CloseReceived))
		{
			return;
		}

		await _sendLock.WaitAsync(cancellationToken);
		try
		{
			if (Socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
			{
				try
				{
					await Socket.CloseAsync(status, description, cancellationToken);
				}
				catch (Exception exception) when (exception is WebSocketException or ObjectDisposedException)
				{
				}
			}
		}
		finally
		{
			_sendLock.Release();
		}
	}

	public void Abort()
	{
		if (Socket.State is WebSocketState.Open or WebSocketState.CloseReceived or WebSocketState.CloseSent)
		{
			Socket.Abort();
		}
	}

	public async ValueTask DisposeAsync()
	{
		if (Interlocked.Exchange(ref _disposed, 1) != 0)
		{
			return;
		}

		try
		{
			await CloseAsync(WebSocketCloseStatus.NormalClosure, "Session disposed");
		}
		catch (WebSocketException)
		{
			// The peer may already have disconnected.
		}
		finally
		{
			Socket.Dispose();
			_sendLock.Dispose();
		}
	}

	private async Task SendAsync(ReadOnlyMemory<byte> message, WebSocketMessageType messageType, CancellationToken cancellationToken)
	{
		ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
		await _sendLock.WaitAsync(cancellationToken);
		try
		{
			if (Socket.State != WebSocketState.Open)
			{
				throw new WebSocketException(WebSocketError.InvalidState, $"WebSocket session '{Id}' is not open.");
			}

			await Socket.SendAsync(message, messageType, true, cancellationToken);
			Interlocked.Exchange(ref _lastSentUnixMilliseconds, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
			_metrics?.RecordWebSocketMessageSent(message.Length);
		}
		finally
		{
			_sendLock.Release();
		}
	}

	private static string? ResolveUserId(ClaimsPrincipal user)
	{
		return user.FindFirstValue(ClaimTypes.NameIdentifier)
			?? user.FindFirstValue("sub")
			?? user.Identity?.Name;
	}
}
