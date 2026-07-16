// Copyright (c) 2026 - opx
using System.Threading;

namespace Opx.Api.Web.Protection;

public sealed class OpxProtectionMetrics
{
	private long _authorizationBypassed;
	private long _authorizationBlocked;
	private long _proxyHits;
	private long _rateLimitBlocked;
	private long _securityIssueLogsDropped;
	private long _securityIssueLogsQueued;
	private long _suspiciousBlocked;
	private long _suspiciousDetected;
	private long _webSocketActiveConnections;
	private long _webSocketConnectionsAccepted;
	private long _webSocketConnectionsClosed;
	private long _webSocketMessagesReceived;
	private long _webSocketMessagesSent;
	private long _webSocketBytesReceived;
	private long _webSocketBytesSent;
	private long _webSocketRejectedMessages;

	public long AuthorizationBypassed => Interlocked.Read(ref _authorizationBypassed);
	public long AuthorizationBlocked => Interlocked.Read(ref _authorizationBlocked);
	public long ProxyHits => Interlocked.Read(ref _proxyHits);
	public long RateLimitBlocked => Interlocked.Read(ref _rateLimitBlocked);
	public long SecurityIssueLogsDropped => Interlocked.Read(ref _securityIssueLogsDropped);
	public long SecurityIssueLogsQueued => Interlocked.Read(ref _securityIssueLogsQueued);
	public long SuspiciousBlocked => Interlocked.Read(ref _suspiciousBlocked);
	public long SuspiciousDetected => Interlocked.Read(ref _suspiciousDetected);
	public long WebSocketActiveConnections => Interlocked.Read(ref _webSocketActiveConnections);
	public long WebSocketConnectionsAccepted => Interlocked.Read(ref _webSocketConnectionsAccepted);
	public long WebSocketConnectionsClosed => Interlocked.Read(ref _webSocketConnectionsClosed);
	public long WebSocketMessagesReceived => Interlocked.Read(ref _webSocketMessagesReceived);
	public long WebSocketMessagesSent => Interlocked.Read(ref _webSocketMessagesSent);
	public long WebSocketBytesReceived => Interlocked.Read(ref _webSocketBytesReceived);
	public long WebSocketBytesSent => Interlocked.Read(ref _webSocketBytesSent);
	public long WebSocketRejectedMessages => Interlocked.Read(ref _webSocketRejectedMessages);

	public void IncrementAuthorizationBypassed() => Interlocked.Increment(ref _authorizationBypassed);
	public void IncrementAuthorizationBlocked() => Interlocked.Increment(ref _authorizationBlocked);
	public void IncrementProxyHits() => Interlocked.Increment(ref _proxyHits);
	public void IncrementRateLimitBlocked() => Interlocked.Increment(ref _rateLimitBlocked);
	public void IncrementSecurityIssueLogsDropped() => Interlocked.Increment(ref _securityIssueLogsDropped);
	public void IncrementSecurityIssueLogsQueued() => Interlocked.Increment(ref _securityIssueLogsQueued);
	public void IncrementSuspiciousBlocked() => Interlocked.Increment(ref _suspiciousBlocked);
	public void IncrementSuspiciousDetected() => Interlocked.Increment(ref _suspiciousDetected);
	public void IncrementWebSocketConnected()
	{
		Interlocked.Increment(ref _webSocketConnectionsAccepted);
		Interlocked.Increment(ref _webSocketActiveConnections);
	}
	public void IncrementWebSocketDisconnected()
	{
		Interlocked.Increment(ref _webSocketConnectionsClosed);
		Interlocked.Decrement(ref _webSocketActiveConnections);
	}
	public void RecordWebSocketMessageReceived(int bytes)
	{
		Interlocked.Increment(ref _webSocketMessagesReceived);
		Interlocked.Add(ref _webSocketBytesReceived, bytes);
	}
	public void RecordWebSocketMessageSent(int bytes)
	{
		Interlocked.Increment(ref _webSocketMessagesSent);
		Interlocked.Add(ref _webSocketBytesSent, bytes);
	}
	public void IncrementWebSocketRejectedMessage() => Interlocked.Increment(ref _webSocketRejectedMessages);

	public object Snapshot()
	{
		return new
		{
			SuspiciousDetected,
			SuspiciousBlocked,
			SecurityIssueLogsQueued,
			SecurityIssueLogsDropped,
			RateLimitBlocked,
			AuthorizationBypassed,
			AuthorizationBlocked,
			ProxyHits,
			WebSocketActiveConnections,
			WebSocketConnectionsAccepted,
			WebSocketConnectionsClosed,
			WebSocketMessagesReceived,
			WebSocketMessagesSent,
			WebSocketBytesReceived,
			WebSocketBytesSent,
			WebSocketRejectedMessages
		};
	}
}
