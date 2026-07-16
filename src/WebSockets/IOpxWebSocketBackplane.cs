// Copyright (c) 2026 - opx
namespace Opx.Api.Web.WebSockets;

public sealed record OpxWebSocketBackplaneMessage(
	string Origin,
	string Target,
	string? Key,
	string Payload);

public interface IOpxWebSocketBackplane
{
	bool Enabled { get; }
	bool IsConnected { get; }
	void SetReceiver(Func<OpxWebSocketBackplaneMessage, CancellationToken, ValueTask> receiver);
	ValueTask PublishAsync(OpxWebSocketBackplaneMessage message, CancellationToken cancellationToken = default);
}

public sealed record OpxWebSocketHealthSnapshot(
	int ActiveConnections,
	int ConnectedUsers,
	int Topics,
	bool BackplaneEnabled,
	bool BackplaneConnected,
	DateTimeOffset Timestamp);
