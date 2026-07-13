// Copyright (c) 2026 - opx
using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Primitives;
using Opx.Api.Web.Common;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxRateLimitingMiddleware
{
	private static readonly ConcurrentDictionary<string, RateLimitBucket> Buckets = new();
	private readonly IConfiguration _configuration;
	private readonly OpxProtectionMetrics? _metrics;
	private readonly OpxProtectionPolicyProvider? _policyProvider;
	private readonly RequestDelegate _next;
	private readonly object _settingsLock = new();
	private IChangeToken? _changeToken;
	private RateLimitingSettings? _settings;
	private long _cleanupGate;

	public OpxRateLimitingMiddleware(
		RequestDelegate next,
		IConfiguration configuration,
		OpxProtectionMetrics? metrics = null,
		OpxProtectionPolicyProvider? policyProvider = null)
	{
		_next = next;
		_configuration = configuration;
		_metrics = metrics;
		_policyProvider = policyProvider;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		var policy = _policyProvider?.GetPolicy(context.Request.Path) ?? OpxProtectionPolicy.Empty;
		var settings = GetSettings();
		if (!settings.Enabled || policy.SkipRateLimiting)
		{
			await _next(context);
			return;
		}

		var limit = Math.Max(1, policy.RateLimit ?? settings.Limit);
		var windowSeconds = Math.Max(1, policy.RateLimitWindowSeconds ?? settings.WindowSeconds);
		var window = TimeSpan.FromSeconds(windowSeconds);
		var pathPrefix = GetPathPrefix(context.Request.Path, settings.PathPrefixes);
		var ipAddress = GetClientIpAddress(context);
		var key = $"{ipAddress}:{pathPrefix}";
		var now = DateTimeOffset.UtcNow;
		CleanupExpiredBuckets(now, settings.CleanupIntervalSeconds);
		var bucket = Buckets.GetOrAdd(key, _ => new RateLimitBucket());
		var result = bucket.Hit(now, limit, window, settings.Algorithm);

		if (!result.Allowed)
		{
			SetRateLimitHeaders(context, limit, result.Remaining, result.ResetSeconds);
			_metrics?.IncrementRateLimitBlocked();
			await WriteTooManyRequestsAsync(context, result.ResetSeconds);
			return;
		}

		if (settings.WriteHeadersOnSuccess)
		{
			SetRateLimitHeaders(context, limit, result.Remaining, result.ResetSeconds);
		}

		await _next(context);
	}

	private RateLimitingSettings GetSettings()
	{
		var currentToken = _configuration.GetReloadToken();
		if (_settings is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
		{
			return _settings;
		}

		lock (_settingsLock)
		{
			currentToken = _configuration.GetReloadToken();
			if (_settings is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
			{
				return _settings;
			}

			_settings = new RateLimitingSettings(
				_configuration.GetValue("OpxApiProtection:RateLimiting:Enabled", false),
				Math.Max(1, _configuration.GetValue("OpxApiProtection:RateLimiting:Limit", 60)),
				Math.Max(1, _configuration.GetValue("OpxApiProtection:RateLimiting:WindowSeconds", 60)),
				Math.Max(1, _configuration.GetValue("OpxApiProtection:RateLimiting:CleanupIntervalSeconds", 60)),
				_configuration.GetValue("OpxApiProtection:RateLimiting:WriteHeadersOnSuccess", true),
				_configuration.GetValue("OpxApiProtection:RateLimiting:Algorithm", "SlidingWindow") ?? "SlidingWindow",
				(_configuration.GetSection("OpxApiProtection:RateLimiting:PathPrefixes").Get<string[]>() ?? [])
					.Where(prefix => !string.IsNullOrWhiteSpace(prefix))
					.OrderByDescending(prefix => prefix.Length)
					.ToArray());
			_changeToken = currentToken;
			return _settings;
		}
	}

	private static string GetPathPrefix(PathString path, string[] prefixes)
	{
		var pathValue = path.Value ?? "/";
		var configuredPrefix = prefixes
			.FirstOrDefault(prefix => pathValue.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

		if (!string.IsNullOrWhiteSpace(configuredPrefix))
		{
			return configuredPrefix;
		}

		var segments = pathValue.Split('/', StringSplitOptions.RemoveEmptyEntries);
		return segments.Length == 0 ? "/" : $"/{segments[0]}";
	}

	private void CleanupExpiredBuckets(DateTimeOffset now, int cleanupIntervalSeconds)
	{
		var currentTicks = now.ToUnixTimeSeconds();
		var lastCleanup = Interlocked.Read(ref _cleanupGate);
		if (currentTicks - lastCleanup < cleanupIntervalSeconds
			|| Interlocked.CompareExchange(ref _cleanupGate, currentTicks, lastCleanup) != lastCleanup)
		{
			return;
		}

		foreach (var item in Buckets)
		{
			if (item.Value.IsExpired(now))
			{
				Buckets.TryRemove(item.Key, out _);
			}
		}
	}

	private static string GetClientIpAddress(HttpContext context)
	{
		if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor)
			&& !string.IsNullOrWhiteSpace(forwardedFor))
		{
			return forwardedFor.ToString().Split(',')[0].Trim();
		}

		return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
	}

	private static void SetRateLimitHeaders(HttpContext context, int limit, int remaining, int resetSeconds)
	{
		context.Response.Headers["RateLimit-Limit"] = limit.ToString();
		context.Response.Headers["RateLimit-Remaining"] = remaining.ToString();
		context.Response.Headers["RateLimit-Reset"] = resetSeconds.ToString();
		context.Response.Headers["X-RateLimit-Limit"] = limit.ToString();
		context.Response.Headers["X-RateLimit-Remaining"] = remaining.ToString();
		context.Response.Headers["X-RateLimit-Reset"] = resetSeconds.ToString();
	}

	private static async Task WriteTooManyRequestsAsync(HttpContext context, int retryAfterSeconds)
	{
		context.Response.Headers.RetryAfter = retryAfterSeconds.ToString();
		await ApiResponseObjectValue.ShowErrorResponseAsync(context, (int)HttpStatusCode.TooManyRequests, new ApiErrorValue
		{
			Message = "Too Many Requests",
			Id = "RateLimit",
			ObjectName = context.Request.Path.ToString()
		});
	}

	private sealed class RateLimitBucket
	{
		private int _fixedCount;
		private DateTimeOffset _fixedWindowStart;
		private readonly Queue<DateTimeOffset> _hits = new();

		public RateLimitResult Hit(DateTimeOffset now, int limit, TimeSpan window, string algorithm)
		{
			return algorithm.Equals("FixedWindow", StringComparison.OrdinalIgnoreCase)
				? HitFixedWindow(now, limit, window)
				: HitSlidingWindow(now, limit, window);
		}

		private RateLimitResult HitFixedWindow(DateTimeOffset now, int limit, TimeSpan window)
		{
			lock (_hits)
			{
				if (_fixedWindowStart == default || now - _fixedWindowStart >= window)
				{
					_fixedWindowStart = now;
					_fixedCount = 0;
				}

				var allowed = _fixedCount < limit;
				if (allowed)
				{
					_fixedCount++;
				}

				var reset = Math.Max(1, (int)Math.Ceiling((window - (now - _fixedWindowStart)).TotalSeconds));
				var remaining = Math.Max(0, limit - _fixedCount);
				return new RateLimitResult(allowed, remaining, reset);
			}
		}

		private RateLimitResult HitSlidingWindow(DateTimeOffset now, int limit, TimeSpan window)
		{
			lock (_hits)
			{
				while (_hits.Count > 0 && now - _hits.Peek() >= window)
				{
					_hits.Dequeue();
				}

				var allowed = _hits.Count < limit;
				if (allowed)
				{
					_hits.Enqueue(now);
				}

				var oldest = _hits.Count > 0 ? _hits.Peek() : now;
				var reset = Math.Max(1, (int)Math.Ceiling((window - (now - oldest)).TotalSeconds));
				var remaining = Math.Max(0, limit - _hits.Count);

				return new RateLimitResult(allowed, remaining, reset);
			}
		}

		public bool IsExpired(DateTimeOffset now)
		{
			lock (_hits)
			{
				var slidingExpired = _hits.Count == 0 || now - _hits.Peek() >= TimeSpan.FromMinutes(5);
				var fixedExpired = _fixedWindowStart == default || now - _fixedWindowStart >= TimeSpan.FromMinutes(5);
				return slidingExpired && fixedExpired;
			}
		}
	}

	private sealed record RateLimitResult(bool Allowed, int Remaining, int ResetSeconds);

	private sealed record RateLimitingSettings(
		bool Enabled,
		int Limit,
		int WindowSeconds,
		int CleanupIntervalSeconds,
		bool WriteHeadersOnSuccess,
		string Algorithm,
		string[] PathPrefixes);
}
