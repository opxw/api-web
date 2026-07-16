// Copyright (c) 2026 - opx
namespace Opx.Api.Web.WebSockets;

public sealed class OpxWebSocketOptions
{
	public bool Enabled { get; set; }
	public string Path { get; set; } = "/opx/ws";
	public bool RequireAuthorization { get; set; } = true;
	public string? SubProtocol { get; set; }
	public int KeepAliveIntervalSeconds { get; set; } = 30;
	public int KeepAliveTimeoutSeconds { get; set; } = 15;
	public int ReceiveBufferBytes { get; set; } = 16 * 1024;
	public int MaxMessageBytes { get; set; } = 1024 * 1024;
	public int IdleTimeoutSeconds { get; set; } = 120;
	public int MessageRateLimit { get; set; } = 120;
	public int MessageRateLimitWindowSeconds { get; set; } = 60;
	public bool EnableTypedRouting { get; set; } = true;
	public bool EnableAcknowledgements { get; set; } = true;
	public int MaxSubscriptionsPerConnection { get; set; } = 64;
	public int MaxTopicLength { get; set; } = 128;
	public OpxWebSocketRedisOptions Redis { get; set; } = new();
	public string[] AllowedOrigins { get; set; } = [];
}

public sealed class OpxWebSocketRedisOptions
{
	public bool Enabled { get; set; }
	public string Configuration { get; set; } = "localhost:6379";
	public string Channel { get; set; } = "opx:websocket";
}
