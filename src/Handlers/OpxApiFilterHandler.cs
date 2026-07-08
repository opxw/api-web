// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Mvc.Filters;
using Opx.Api.Web.Common;

namespace Opx.Api.Web.Handlers
{
	public class OpxApiFilterHandler : ActionFilterAttribute
	{
		public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
		{
			if (!context.ModelState.IsValid)
			{
				var errorNames = string.Join(",", context.ModelState.Keys.ToList());

				var errorValue = new ApiErrorValue()
				{
					Message = "No data sent : " + errorNames,
					ObjectName = ApiResponseObjectValue.GetRouteNameFromContext(context),
					Id = ((Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor)context.ActionDescriptor).ActionName,
				};

				await ApiResponseObjectValue.ShowErrorResponseAsync(context.HttpContext, 400, errorValue);
			}
			else
			{
				await base.OnActionExecutionAsync(context, next);
			}

			return;
		}
	}
}
