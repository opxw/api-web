// Copyright (c) 2026 - opx
namespace Opx.Api.Web.WebSockets;

internal sealed class OpxWebSocketLifetimeService : IHostedService
{
	private readonly OpxWebSocketConnectionManager _connections;

	public OpxWebSocketLifetimeService(OpxWebSocketConnectionManager connections)
	{
		_connections = connections;
	}

	public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

	public Task StopAsync(CancellationToken cancellationToken)
	{
		return _connections.CloseAllAsync(cancellationToken);
	}
}
