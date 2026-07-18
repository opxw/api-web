// Copyright (c) 2026 - opx
using Microsoft.Extensions.Options;
using Opx.Api.Web.Options;
using System.Text.Json.Serialization;

namespace Opx.Api.Web.Common;

public static class OpxApiResponseWriter
{
	private const string LogicalStatusCodeKey = "Opx.Api.Web.LogicalStatusCode";

	public static Task WriteErrorAsync(
		HttpContext context,
		int statusCode,
		string message,
		CancellationToken cancellationToken = default)
	{
		return WriteErrorAsync(
			context,
			statusCode,
			new OpxApiErrorMessage(message),
			cancellationToken);
	}

	public static Task WriteErrorAsync(
		HttpContext context,
		int statusCode,
		object? data,
		CancellationToken cancellationToken = default)
	{
		return ApiResponseObjectValue.ShowErrorResponseAsync(
			context,
			statusCode,
			data,
			completeResponse: false,
			cancellationToken: cancellationToken);
	}

	public static int GetLogicalStatusCode(HttpContext context)
	{
		return context.Items.TryGetValue(LogicalStatusCodeKey, out var value) && value is int statusCode
			? statusCode
			: context.Response.StatusCode;
	}

	internal static int ResolveHttpStatusCode(HttpContext context, int logicalStatusCode)
	{
		context.Items[LogicalStatusCodeKey] = logicalStatusCode;
		var options = context.RequestServices?
			.GetService<IOptionsMonitor<OpxApiErrorResponseOptions>>()?
			.CurrentValue;
		return options?.HttpStatusMode == OpxApiHttpStatusMode.Original
			? logicalStatusCode
			: StatusCodes.Status200OK;
	}

	private sealed record OpxApiErrorMessage(
		[property: JsonPropertyName("message")] string Message);
}
