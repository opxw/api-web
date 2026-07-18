// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Opx.Api.Web.Options;
using System.Globalization;
using System.Text.Json;

namespace Opx.Api.Web.Common
{
	internal static class ApiResponseObjectValue
	{
		public static Task ShowErrorResponseAsync(HttpContext context, int? statusCode, object? errorValue,
			double? elapsedTime = null, bool completeResponse = true,
			CancellationToken cancellationToken = default)
		{
			var originStatusCode = statusCode ?? context.Response.StatusCode;
			return WriteResponseAsync(
				context,
				false,
				errorValue,
				originStatusCode,
				elapsedTime,
				completeResponse,
				cancellationToken);
		}

		public static Task ShowResponseAsync(HttpContext context, object? data, double? elapsedTime = null)
		{
			return WriteResponseAsync(context, true, data, StatusCodes.Status200OK, elapsedTime, false, default);
		}

		public static string GetRouteNameFromContext(FilterContext context)
		{
			var routeName = context.RouteData.Values["Controller"]?.ToString();
			return !string.IsNullOrWhiteSpace(routeName) ? routeName : string.Empty;
		}

		public static double GetExecutionTime(HttpContext context, bool inSec = true)
		{
			double result = 0;

			if (context.Items.TryGetValue("StartTime", out var startTimeObj) && startTimeObj is DateTime startTime)
			{
				result = (DateTime.UtcNow - startTime).TotalMilliseconds;
			}

			if (inSec)
				result = TimeSpan.FromMilliseconds(result).TotalSeconds;

			return Math.Round(result, 4);
		}

		private static async Task WriteResponseAsync(HttpContext context, bool resultStatus, object? data,
			int logicalStatusCode, double? elapsedTime, bool completeResponse,
			CancellationToken cancellationToken)
		{
			var result = new ApiResult()
			{
				Result = resultStatus,
				Data = data,
				StatusCode = logicalStatusCode.ToString(CultureInfo.InvariantCulture)
			};
			var response = JsonSerializer.SerializeToUtf8Bytes(result);

			context.Response.ContentType = "application/json";
			context.Response.StatusCode = resultStatus
				? StatusCodes.Status200OK
				: OpxApiResponseWriter.ResolveHttpStatusCode(context, logicalStatusCode);
			context.Response.ContentLength = response.Length;

			var responseHeaderOptions = context.RequestServices?
				.GetService<IOptionsMonitor<OpxApiResponseHeaderOptions>>()?
				.CurrentValue;
			if (responseHeaderOptions?.ExposeExecutionTime != false)
			{
				var executionTime = elapsedTime ?? GetExecutionTime(context);
				context.Response.Headers["Execution-Time"] = executionTime.ToString(CultureInfo.InvariantCulture);
			}
			else
			{
				context.Response.Headers.Remove("Execution-Time");
			}

			await context.Response.Body.WriteAsync(response, cancellationToken);

			if (completeResponse)
				await context.Response.CompleteAsync();
		}
	}
}
