// Copyright (c) 2026 - opx
using System.Net;

namespace Opx.Api.Web.Common
{
	public static class ApiExtension
	{
		public static async Task HandleUncatchedStatusCodeAsync(this WebApplication app, HttpContext context, string sender = "")
		{
			var statusCode = context.Response.StatusCode;

			// Successful and redirect/cache responses (including 204 and 304) must retain
			// their original status and body semantics. Only wrap actual HTTP errors.
			if (statusCode < (int)HttpStatusCode.BadRequest)
				return;

			var controller = context.Request.RouteValues["controller"];
			var action = context.Request.RouteValues["action"];

			var error = new ApiErrorValue()
			{
				Id = action?.ToString() ?? ((HttpStatusCode)context.Response.StatusCode).ToString(),
				ObjectName = controller?.ToString() ?? context.Request.Path.ToString(),
			};

			string message = statusCode switch
			{
				(int)HttpStatusCode.Unauthorized => "Unauthorized",
				(int)HttpStatusCode.BadRequest => "Bad request",
				(int)HttpStatusCode.Forbidden => "Forbidden",
				(int)HttpStatusCode.NotFound => "Not found",
				(int)HttpStatusCode.MethodNotAllowed => "HTTP Method not allowed",
				(int)HttpStatusCode.ServiceUnavailable => "Unavailable",
				(int)HttpStatusCode.NoContent => "No content",
				(int)HttpStatusCode.InternalServerError => "Internal server error",
				(int)HttpStatusCode.UnsupportedMediaType => "Unsupported Media Type",
				_ => ((HttpStatusCode)statusCode).ToString()
			};

			error.Message = message;

			await ApiResponseObjectValue.ShowErrorResponseAsync(context, statusCode, error);
		}
	}
}
