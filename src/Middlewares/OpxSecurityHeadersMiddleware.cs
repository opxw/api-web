// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Middlewares;

public sealed class OpxSecurityHeadersMiddleware
{
	private readonly RequestDelegate _next;
	private readonly IConfiguration _configuration;

	public OpxSecurityHeadersMiddleware(RequestDelegate next, IConfiguration configuration)
	{
		_next = next;
		_configuration = configuration;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		if (!_configuration.GetValue("OpxApiProtection:SecurityHeaders:Enabled", true))
		{
			await _next(context);
			return;
		}

		ApplyHeaders(context);
		context.Response.OnStarting(() =>
		{
			ApplyHeaders(context);
			return Task.CompletedTask;
		});

		await _next(context);
		if (!context.Response.HasStarted)
			ApplyHeaders(context);
	}

	private void ApplyHeaders(HttpContext context)
	{
		var headers = context.Response.Headers;
		headers["X-Content-Type-Options"] = "nosniff";
		headers["Referrer-Policy"] = _configuration.GetValue("OpxApiProtection:SecurityHeaders:ReferrerPolicy", "no-referrer");
		headers["X-Frame-Options"] = _configuration.GetValue("OpxApiProtection:SecurityHeaders:FrameOptions", "DENY");
		headers.Remove("Server");
		headers.Remove("X-Powered-By");
	}
}
