using Microsoft.AspNetCore.Mvc;
using Opx.Api.Infrastructure.Service;
using System.Net;

namespace Opx.Api.Web.Common
{
	public class OpxApiController : ControllerBase
	{
		protected async Task OkAsync(object? data)
		{
			if (data is AppResult appResult)
			{
				await OkOrFailAsync(appResult);
				return;
			}

			await ApiResponseObjectValue.ShowResponseAsync(HttpContext, data);
		}

		protected async Task OkAsync(Task<AppResult> resultTask)
		{
			await OkOrFailAsync(await resultTask);
		}

		protected async Task OkOrFailAsync(AppResult result)
		{
			if (result.Result)
			{
				await ApiResponseObjectValue.ShowResponseAsync(HttpContext, result.Data);
				return;
			}

			await FailAsync(CreateErrorData(result), GetStatusCode(result));
		}

		protected async Task OkOrFailAsync(Task<AppResult> resultTask)
		{
			await OkOrFailAsync(await resultTask);
		}

		protected async Task FailAsync(object? data, int statusCode = (int)HttpStatusCode.BadRequest)
		{
			await ApiResponseObjectValue.ShowErrorResponseAsync(HttpContext, statusCode, data);
		}

		private static int GetStatusCode(AppResult result)
		{
			return result.Source switch
			{
				AppResult.ValidationErrorSource => (int)HttpStatusCode.BadRequest,
				AppResult.ExceptionErrorSource => (int)HttpStatusCode.InternalServerError,
				_ => (int)HttpStatusCode.BadRequest
			};
		}

		private object? CreateErrorData(AppResult result)
		{
			if (result.Data is not null)
			{
				return result.Data;
			}

			return new ApiErrorValue
			{
				Id = ControllerContext.RouteData?.Values["action"]?.ToString() ?? result.Source.ToString(),
				ObjectName = ControllerContext.RouteData?.Values["controller"]?.ToString() ?? HttpContext.Request.Path.ToString(),
				Message = result.Message ?? GetStatusMessage(result)
			};
		}

		private static string GetStatusMessage(AppResult result)
		{
			return result.Source switch
			{
				AppResult.ValidationErrorSource => "Bad request",
				AppResult.ExceptionErrorSource => "Internal server error",
				_ => "Bad request"
			};
		}
	}
}
