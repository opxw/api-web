// Copyright (c) 2026 - opx
using System.Net.WebSockets;

namespace Opx.Api.Web.WebSockets;

public interface IOpxWebSocketHandler
{
	ValueTask OnConnectedAsync(OpxWebSocketSession session, CancellationToken cancellationToken);
	ValueTask OnTextMessageAsync(OpxWebSocketSession session, ReadOnlyMemory<byte> utf8Message, CancellationToken cancellationToken);
	ValueTask OnBinaryMessageAsync(OpxWebSocketSession session, ReadOnlyMemory<byte> message, CancellationToken cancellationToken);
	ValueTask OnDisconnectedAsync(OpxWebSocketSession session, WebSocketCloseStatus? closeStatus, string? description, CancellationToken cancellationToken);
}

public abstract class OpxWebSocketHandler : IOpxWebSocketHandler
{
	public virtual ValueTask OnConnectedAsync(OpxWebSocketSession session, CancellationToken cancellationToken) => ValueTask.CompletedTask;
	public virtual ValueTask OnTextMessageAsync(OpxWebSocketSession session, ReadOnlyMemory<byte> utf8Message, CancellationToken cancellationToken) => ValueTask.CompletedTask;
	public virtual ValueTask OnBinaryMessageAsync(OpxWebSocketSession session, ReadOnlyMemory<byte> message, CancellationToken cancellationToken) => ValueTask.CompletedTask;
	public virtual ValueTask OnDisconnectedAsync(OpxWebSocketSession session, WebSocketCloseStatus? closeStatus, string? description, CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

internal sealed class OpxNoOpWebSocketHandler : OpxWebSocketHandler;
