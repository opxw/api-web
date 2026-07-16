// Copyright (c) 2026 - opx
namespace Opx.Api.Web.WebSockets;

public interface IOpxWebSocketMessageHandler
{
	string Type { get; }
	ValueTask HandleAsync(OpxWebSocketSession session, OpxWebSocketMessage message, CancellationToken cancellationToken);
}

public abstract class OpxWebSocketMessageHandler<T> : IOpxWebSocketMessageHandler
{
	public abstract string Type { get; }

	public ValueTask HandleAsync(OpxWebSocketSession session, OpxWebSocketMessage message, CancellationToken cancellationToken)
	{
		return HandleAsync(session, message.GetData<T>(), message, cancellationToken);
	}

	protected abstract ValueTask HandleAsync(
		OpxWebSocketSession session,
		T? data,
		OpxWebSocketMessage message,
		CancellationToken cancellationToken);
}

internal sealed class OpxNoOpWebSocketMessageHandler : IOpxWebSocketMessageHandler
{
	public string Type => "opx.noop";
	public ValueTask HandleAsync(OpxWebSocketSession session, OpxWebSocketMessage message, CancellationToken cancellationToken) => ValueTask.CompletedTask;
}
