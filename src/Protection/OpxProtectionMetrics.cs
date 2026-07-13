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

	public long AuthorizationBypassed => Interlocked.Read(ref _authorizationBypassed);
	public long AuthorizationBlocked => Interlocked.Read(ref _authorizationBlocked);
	public long ProxyHits => Interlocked.Read(ref _proxyHits);
	public long RateLimitBlocked => Interlocked.Read(ref _rateLimitBlocked);
	public long SecurityIssueLogsDropped => Interlocked.Read(ref _securityIssueLogsDropped);
	public long SecurityIssueLogsQueued => Interlocked.Read(ref _securityIssueLogsQueued);
	public long SuspiciousBlocked => Interlocked.Read(ref _suspiciousBlocked);
	public long SuspiciousDetected => Interlocked.Read(ref _suspiciousDetected);

	public void IncrementAuthorizationBypassed() => Interlocked.Increment(ref _authorizationBypassed);
	public void IncrementAuthorizationBlocked() => Interlocked.Increment(ref _authorizationBlocked);
	public void IncrementProxyHits() => Interlocked.Increment(ref _proxyHits);
	public void IncrementRateLimitBlocked() => Interlocked.Increment(ref _rateLimitBlocked);
	public void IncrementSecurityIssueLogsDropped() => Interlocked.Increment(ref _securityIssueLogsDropped);
	public void IncrementSecurityIssueLogsQueued() => Interlocked.Increment(ref _securityIssueLogsQueued);
	public void IncrementSuspiciousBlocked() => Interlocked.Increment(ref _suspiciousBlocked);
	public void IncrementSuspiciousDetected() => Interlocked.Increment(ref _suspiciousDetected);

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
			ProxyHits
		};
	}
}
