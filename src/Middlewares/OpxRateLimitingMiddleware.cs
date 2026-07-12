// Copyright (c) 2026 - opx
using System.Collections.Concurrent;
using System.Net;
using Opx.Api.Web.Common;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxRateLimitingMiddleware
{
	private static readonly ConcurrentDictionary<string, RateLimitBucket> Buckets = new();
	private readonly IConfiguration _configuration;
	private readonly RequestDelegate _next;

	public OpxRateLimitingMiddleware(RequestDelegate next, IConfiguration configuration)
	{
		_next = next;
		_configuration = configuration;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		if (!_configuration.GetValue("OpxApiProtection:RateLimiting:Enabled", false))
		{
			await _next(context);
			return;
		}

		var limit = Math.Max(1, _configuration.GetValue("OpxApiProtection:RateLimiting:Limit", 60));
		var windowSeconds = Math.Max(1, _configuration.GetValue("OpxApiProtection:RateLimiting:WindowSeconds", 60));
		var pathPrefix = GetPathPrefix(context.Request.Path);
		var ipAddress = GetClientIpAddress(context);
		var key = $"{ipAddress}:{pathPrefix}";
		var now = DateTimeOffset.UtcNow;
		var bucket = Buckets.GetOrAdd(key, _ => new RateLimitBucket());
		var result = bucket.Hit(now, limit, TimeSpan.FromSeconds(windowSeconds));

		SetRateLimitHeaders(context, limit, result.Remaining, result.ResetSeconds);

		if (!result.Allowed)
		{
			await WriteTooManyRequestsAsync(context, result.ResetSeconds);
			return;
		}

		await _next(context);
	}

	private string GetPathPrefix(PathString path)
	{
		var prefixes = _configuration
			.GetSection("OpxApiProtection:RateLimiting:PathPrefixes")
			.Get<string[]>()
			?? [];

		var pathValue = path.Value ?? "/";
		var configuredPrefix = prefixes
			.Where(prefix => !string.IsNullOrWhiteSpace(prefix))
			.OrderByDescending(prefix => prefix.Length)
			.FirstOrDefault(prefix => pathValue.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

		if (!string.IsNullOrWhiteSpace(configuredPrefix))
		{
			return configuredPrefix;
		}

		var segments = pathValue.Split('/', StringSplitOptions.RemoveEmptyEntries);
		return segments.Length == 0 ? "/" : $"/{segments[0]}";
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
		private readonly Queue<DateTimeOffset> _hits = new();

		public RateLimitResult Hit(DateTimeOffset now, int limit, TimeSpan window)
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
	}

	private sealed record RateLimitResult(bool Allowed, int Remaining, int ResetSeconds);
}

