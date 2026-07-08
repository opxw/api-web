// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Mvc.Filters;
using System.Globalization;
using System.Text.Json;

namespace Opx.Api.Web.Common
{
	internal static class ApiResponseObjectValue
	{
		public static Task ShowErrorResponseAsync(HttpContext context, int? statusCode, object? errorValue,
			double? elapsedTime = null)
		{
			var originStatusCode = statusCode ?? context.Response.StatusCode;
			return WriteResponseAsync(context, false, errorValue, originStatusCode.ToString(), elapsedTime, true);
		}

		public static Task ShowResponseAsync(HttpContext context, object? data, double? elapsedTime = null)
		{
			return WriteResponseAsync(context, true, data, "200", elapsedTime, false);
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
			string statusCode, double? elapsedTime, bool completeResponse)
		{
			var result = new ApiResult()
			{
				Result = resultStatus,
				Data = data,
				StatusCode = statusCode
			};
			var response = JsonSerializer.SerializeToUtf8Bytes(result);
			var executionTime = elapsedTime ?? GetExecutionTime(context);

			context.Response.ContentType = "application/json";
			context.Response.StatusCode = 200;
			context.Response.ContentLength = response.Length;
			context.Response.Headers["Execution-Time"] = executionTime.ToString(CultureInfo.InvariantCulture);

			await context.Response.Body.WriteAsync(response);

			if (completeResponse)
				await context.Response.CompleteAsync();
		}
	}
}
