// Copyright (c) 2026 - opx
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Opx.Api.Web.Common;

namespace Opx.Api.Web.Middlewares;

public sealed class OpxAuthorizationGuardMiddleware
{
	private readonly IConfiguration _configuration;
	private readonly RequestDelegate _next;

	public OpxAuthorizationGuardMiddleware(RequestDelegate next, IConfiguration configuration)
	{
		_next = next;
		_configuration = configuration;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		if (!_configuration.GetValue("OpxApiProtection:AuthorizationGuard:Enabled", false)
			|| IsExcluded(context)
			|| HasAllowAnonymous(context))
		{
			await _next(context);
			return;
		}

		var result = await context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
		if (!result.Succeeded || result.Principal?.Identity?.IsAuthenticated != true)
		{
			await ApiResponseObjectValue.ShowErrorResponseAsync(context, (int)HttpStatusCode.Unauthorized, new ApiErrorValue
			{
				Message = "Unauthorized",
				Id = "AuthorizationGuard",
				ObjectName = context.Request.Path.ToString()
			});
			return;
		}

		context.User = result.Principal;
		await _next(context);
	}

	private bool IsExcluded(HttpContext context)
	{
		var prefixes = _configuration
			.GetSection("OpxApiProtection:AuthorizationGuard:ExcludedPathPrefixes")
			.Get<string[]>()
			?? ["/health", "/swagger", "/openapi"];

		var path = context.Request.Path.ToString();
		return prefixes.Any(prefix => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
	}

	private static bool HasAllowAnonymous(HttpContext context)
	{
		return context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is not null;
	}
}

