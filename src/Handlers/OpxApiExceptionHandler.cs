using Microsoft.AspNetCore.Mvc.Filters;
using Opx.Api.Web.Common;

namespace Opx.Api.Web.Handlers
{
	public class OpxApiExceptionHandler : ExceptionFilterAttribute
	{
		public override async Task OnExceptionAsync(ExceptionContext context)
		{
			context.ExceptionHandled = true;

			var errorValue = new ApiErrorValue()
			{
				Id = ((Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor)context.ActionDescriptor).ActionName,
				Message = context.Exception.Message,
				ObjectName = ApiResponseObjectValue.GetRouteNameFromContext(context)
			};

			await ApiResponseObjectValue.ShowErrorResponseAsync(context.HttpContext, 500, errorValue);

			return;
		}
	}
}
