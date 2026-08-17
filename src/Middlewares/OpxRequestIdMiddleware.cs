// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Middlewares;

public sealed class OpxRequestIdMiddleware
{
	public const string HeaderName = "X-Request-ID";
	public const string ItemName = "OpxRequestId";
	private const int MaxLength = 128;
	private readonly RequestDelegate _next;

	public OpxRequestIdMiddleware(RequestDelegate next)
	{
		_next = next;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		var requestId = ResolveRequestId(context);
		context.TraceIdentifier = requestId;
		context.Items[ItemName] = requestId;
		context.Response.Headers[HeaderName] = requestId;
		await _next(context);
	}

	private static string ResolveRequestId(HttpContext context)
	{
		var candidate = context.Request.Headers[HeaderName].FirstOrDefault();
		if (IsValid(candidate))
		{
			return candidate!.Trim();
		}

		return string.IsNullOrWhiteSpace(context.TraceIdentifier)
			? Guid.NewGuid().ToString("N")
			: context.TraceIdentifier;
	}

	private static bool IsValid(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		var candidate = value.Trim();
		if (candidate.Length is 0 or > MaxLength)
		{
			return false;
		}

		foreach (var character in candidate)
		{
			if (!char.IsAsciiLetterOrDigit(character)
				&& character is not '-' and not '_' and not '.' and not ':')
			{
				return false;
			}
		}

		return true;
	}
}
