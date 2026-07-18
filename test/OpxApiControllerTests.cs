// Copyright (c) 2026 - opx
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using Opx.Api.Infrastructure.Service;
using Opx.Api.Web.Common;
using Opx.Api.Web.Handlers;
using Opx.Api.Web.Options;

namespace Opx.Api.Web.Tests;

[TestFixture]
public class OpxApiControllerTests
{
	private static readonly IServiceProvider DefaultServices = new ServiceCollection().BuildServiceProvider();

	[Test]
	public async Task OpxApiExceptionHandler_WithException_WritesInternalServerErrorResponse()
	{
		var httpContext = new DefaultHttpContext();
		httpContext.Items["StartTime"] = DateTime.UtcNow;
		httpContext.Response.Body = new MemoryStream();

		var actionContext = new ActionContext(
			httpContext,
			new RouteData(new RouteValueDictionary
			{
				["controller"] = "User",
				["action"] = "Get"
			}),
			new ControllerActionDescriptor
			{
				ControllerName = "User",
				ActionName = "Get"
			});
		var exceptionContext = new ExceptionContext(actionContext, new List<IFilterMetadata>())
		{
			Exception = new InvalidOperationException("Something failed")
		};

		await new OpxApiExceptionHandler().OnExceptionAsync(exceptionContext);

		var result = await ReadResponseAsync(httpContext);
		var data = result.GetProperty("data");

		Assert.Multiple(() =>
		{
			Assert.That(exceptionContext.ExceptionHandled, Is.True);
			Assert.That(httpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(result.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.InternalServerError).ToString()));
			Assert.That(data.GetProperty("message").GetString(), Is.EqualTo("Something failed"));
			Assert.That(data.GetProperty("id").GetString(), Is.EqualTo("Get"));
			Assert.That(data.GetProperty("objectName").GetString(), Is.EqualTo("User"));
		});
	}

	[Test]
	public async Task HandleUncatchedStatusCodeAsync_WithUnauthorizedPage_WritesUnauthorizedResponse()
	{
		var httpContext = new DefaultHttpContext();
		httpContext.Items["StartTime"] = DateTime.UtcNow;
		httpContext.Request.Path = "/private";
		httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
		httpContext.Response.Body = new MemoryStream();

		await ((WebApplication)null!).HandleUncatchedStatusCodeAsync(httpContext);

		var result = await ReadResponseAsync(httpContext);
		var data = result.GetProperty("data");

		Assert.Multiple(() =>
		{
			Assert.That(httpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(result.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.Unauthorized).ToString()));
			Assert.That(data.GetProperty("message").GetString(), Is.EqualTo("Unauthorized"));
			Assert.That(data.GetProperty("id").GetString(), Is.EqualTo(HttpStatusCode.Unauthorized.ToString()));
			Assert.That(data.GetProperty("objectName").GetString(), Is.EqualTo("/private"));
		});
	}

	[Test]
	public async Task HandleUncatchedStatusCodeAsync_WithNotFoundPage_WritesNotFoundResponse()
	{
		var httpContext = new DefaultHttpContext();
		httpContext.Items["StartTime"] = DateTime.UtcNow;
		httpContext.Request.Path = "/page-not-found";
		httpContext.Response.StatusCode = StatusCodes.Status404NotFound;
		httpContext.Response.Body = new MemoryStream();

		await ((WebApplication)null!).HandleUncatchedStatusCodeAsync(httpContext);

		var result = await ReadResponseAsync(httpContext);
		var data = result.GetProperty("data");

		Assert.Multiple(() =>
		{
			Assert.That(httpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(result.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.NotFound).ToString()));
			Assert.That(data.GetProperty("message").GetString(), Is.EqualTo("Not found"));
			Assert.That(data.GetProperty("id").GetString(), Is.EqualTo(HttpStatusCode.NotFound.ToString()));
			Assert.That(data.GetProperty("objectName").GetString(), Is.EqualTo("/page-not-found"));
		});
	}

	[Test]
	public async Task HandleUncatchedStatusCodeAsync_WithFiveHundredUnauthorizedRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount)
			.Select(async id =>
			{
				var httpContext = new DefaultHttpContext();
				httpContext.Items["StartTime"] = DateTime.UtcNow;
				httpContext.Request.Path = $"/private/{id}";
				httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
				httpContext.Response.Body = new MemoryStream();

				await ((WebApplication)null!).HandleUncatchedStatusCodeAsync(httpContext);

				return await ReadResponseAsync(httpContext);
			})
			.ToArray();

		var results = await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(results, Has.Length.EqualTo(requestCount));
			Assert.That(results.All(result => !result.GetProperty("result").GetBoolean()), Is.True);
			Assert.That(results.All(result => result.GetProperty("statusCode").GetString() == ((int)HttpStatusCode.Unauthorized).ToString()), Is.True);
			Assert.That(stopwatch.Elapsed, Is.LessThanOrEqualTo(TimeSpan.FromSeconds(1)));
		});
	}

	[Test]
	public async Task OpxApiExceptionHandler_WithFiveHundredExceptions_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount)
			.Select(async id =>
			{
				var httpContext = new DefaultHttpContext();
				httpContext.Items["StartTime"] = DateTime.UtcNow;
				httpContext.Response.Body = new MemoryStream();

				var actionContext = new ActionContext(
					httpContext,
					new RouteData(new RouteValueDictionary
					{
						["controller"] = "Stress",
						["action"] = "Exception"
					}),
					new ControllerActionDescriptor
					{
						ControllerName = "Stress",
						ActionName = "Exception"
					});
				var exceptionContext = new ExceptionContext(actionContext, new List<IFilterMetadata>())
				{
					Exception = new InvalidOperationException($"Failure {id}")
				};

				await new OpxApiExceptionHandler().OnExceptionAsync(exceptionContext);

				return await ReadResponseAsync(httpContext);
			})
			.ToArray();

		var results = await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(results, Has.Length.EqualTo(requestCount));
			Assert.That(results.All(result => !result.GetProperty("result").GetBoolean()), Is.True);
			Assert.That(results.All(result => result.GetProperty("statusCode").GetString() == ((int)HttpStatusCode.InternalServerError).ToString()), Is.True);
			Assert.That(stopwatch.Elapsed, Is.LessThanOrEqualTo(TimeSpan.FromSeconds(1)));
		});
	}

	[Test]
	public async Task OkAsync_WithPlainData_WritesSuccessResponse()
	{
		var controller = CreateController();

		await controller.WriteOkAsync(new { Name = "opx" });

		var result = await ReadResponseAsync(controller.HttpContext);

		Assert.Multiple(() =>
		{
			Assert.That(controller.HttpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(result.GetProperty("result").GetBoolean(), Is.True);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo("200"));
			Assert.That(result.GetProperty("data").GetProperty("Name").GetString(), Is.EqualTo("opx"));
			Assert.That(controller.HttpContext.Response.Headers.ContainsKey("Execution-Time"), Is.True);
		});
	}

	[Test]
	public async Task OkAsync_WhenExecutionTimeIsHidden_DoesNotWriteHeader()
	{
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["OpxApiProtection:ResponseHeaders:ExposeExecutionTime"] = "false"
			})
			.Build();
		using var services = new ServiceCollection()
			.AddOptions<OpxApiResponseHeaderOptions>()
			.Bind(configuration.GetSection("OpxApiProtection:ResponseHeaders"))
			.Services
			.BuildServiceProvider();
		var controller = CreateController(services);

		await controller.WriteOkAsync(new { Name = "opx" });

		Assert.That(controller.HttpContext.Response.Headers.ContainsKey("Execution-Time"), Is.False);
	}

	[Test]
	public async Task OkAsync_WhenExecutionTimeSettingReloads_AppliesLatestValue()
	{
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["OpxApiProtection:ResponseHeaders:ExposeExecutionTime"] = "true"
			})
			.Build();
		using var services = new ServiceCollection()
			.AddOptions<OpxApiResponseHeaderOptions>()
			.Bind(configuration.GetSection("OpxApiProtection:ResponseHeaders"))
			.Services
			.BuildServiceProvider();
		var visibleController = CreateController(services);

		await visibleController.WriteOkAsync(new { Name = "visible" });
		configuration["OpxApiProtection:ResponseHeaders:ExposeExecutionTime"] = "false";
		((IConfigurationRoot)configuration).Reload();
		var hiddenController = CreateController(services);
		await hiddenController.WriteOkAsync(new { Name = "hidden" });

		Assert.Multiple(() =>
		{
			Assert.That(visibleController.HttpContext.Response.Headers.ContainsKey("Execution-Time"), Is.True);
			Assert.That(hiddenController.HttpContext.Response.Headers.ContainsKey("Execution-Time"), Is.False);
		});
	}

	[Test]
	public async Task OkOrFailAsync_WithSuccessfulAppResult_AssignsServiceDataToApiResultData()
	{
		var controller = CreateController();
		var serviceResult = new AppResult
		{
			Result = true,
			Data = new { Id = 7, Username = "novi" },
			Source = AppResult.SuccessSource
		};

		await controller.WriteOkOrFailAsync(serviceResult);

		var result = await ReadResponseAsync(controller.HttpContext);
		var data = result.GetProperty("data");

		Assert.Multiple(() =>
		{
			Assert.That(result.GetProperty("result").GetBoolean(), Is.True);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo("200"));
			Assert.That(data.GetProperty("Id").GetInt32(), Is.EqualTo(7));
			Assert.That(data.GetProperty("Username").GetString(), Is.EqualTo("novi"));
		});
	}

	[Test]
	public async Task OkOrFailAsync_WithValidationErrorAppResult_WritesFailResponseWithBadRequestStatusCodeInBody()
	{
		var controller = CreateController();
		var serviceResult = new AppResult
		{
			Result = false,
			Message = "User not found",
			Source = AppResult.ValidationErrorSource
		};

		await controller.WriteOkOrFailAsync(serviceResult);

		var result = await ReadResponseAsync(controller.HttpContext);
		var data = result.GetProperty("data");

		Assert.Multiple(() =>
		{
			Assert.That(controller.HttpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(result.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.BadRequest).ToString()));
			Assert.That(data.GetProperty("message").GetString(), Is.EqualTo("User not found"));
		});
	}

	[Test]
	public async Task OkOrFailAsync_WithExceptionAppResult_WritesFailResponseWithInternalServerErrorStatusCodeInBody()
	{
		var controller = CreateController();
		var serviceResult = new AppResult
		{
			Result = false,
			Message = "Database timeout",
			Source = AppResult.ExceptionErrorSource
		};

		await controller.WriteOkOrFailAsync(serviceResult);

		var result = await ReadResponseAsync(controller.HttpContext);

		Assert.Multiple(() =>
		{
			Assert.That(controller.HttpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
			Assert.That(result.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(result.GetProperty("statusCode").GetString(), Is.EqualTo(((int)HttpStatusCode.InternalServerError).ToString()));
			Assert.That(result.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("Database timeout"));
		});
	}

	[Test]
	public async Task OkOrFailAsync_WithFiveHundredConcurrentRequests_CompletesWithinOneSecond()
	{
		const int requestCount = 500;
		var stopwatch = Stopwatch.StartNew();

		var tasks = Enumerable.Range(0, requestCount)
			.Select(async id =>
			{
				var controller = CreateController();
				await controller.WriteOkOrFailAsync(new AppResult
				{
					Result = true,
					Data = new { Id = id },
					Source = AppResult.SuccessSource
				});

				return await ReadResponseAsync(controller.HttpContext);
			})
			.ToArray();

		var results = await Task.WhenAll(tasks);
		stopwatch.Stop();

		Assert.Multiple(() =>
		{
			Assert.That(results, Has.Length.EqualTo(requestCount));
			Assert.That(results.All(result => result.GetProperty("result").GetBoolean()), Is.True);
			Assert.That(stopwatch.Elapsed, Is.LessThanOrEqualTo(TimeSpan.FromSeconds(1)));
		});
	}

	[TestCase("Always200", StatusCodes.Status200OK)]
	[TestCase("Original", StatusCodes.Status401Unauthorized)]
	public async Task OpxApiResponseWriter_UsesConfiguredHttpStatusMode(
		string mode,
		int expectedHttpStatus)
	{
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["OpxApiProtection:ErrorResponse:HttpStatusMode"] = mode,
				["OpxApiProtection:ResponseHeaders:ExposeExecutionTime"] = "false"
			})
			.Build();
		using var services = new ServiceCollection()
			.AddOpxApiResponseWriter(configuration)
			.BuildServiceProvider();
		var context = new DefaultHttpContext
		{
			RequestServices = services
		};
		context.Response.Body = new MemoryStream();

		await OpxApiResponseWriter.WriteErrorAsync(
			context,
			StatusCodes.Status401Unauthorized,
			"custom unauthorized");
		var response = await ReadResponseAsync(context);

		Assert.Multiple(() =>
		{
			Assert.That(context.Response.StatusCode, Is.EqualTo(expectedHttpStatus));
			Assert.That(response.GetProperty("result").GetBoolean(), Is.False);
			Assert.That(response.GetProperty("data").GetProperty("message").GetString(), Is.EqualTo("custom unauthorized"));
			Assert.That(response.GetProperty("statusCode").GetString(), Is.EqualTo("401"));
			Assert.That(OpxApiResponseWriter.GetLogicalStatusCode(context), Is.EqualTo(StatusCodes.Status401Unauthorized));
		});
	}

	[Test]
	public void AddOpxApiResponseWriter_WhenHttpStatusModeIsInvalid_RejectsOptions()
	{
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["OpxApiProtection:ErrorResponse:HttpStatusMode"] = "99"
			})
			.Build();
		using var services = new ServiceCollection()
			.AddOpxApiResponseWriter(configuration)
			.BuildServiceProvider();

		Assert.Throws<OptionsValidationException>(() =>
			services.GetRequiredService<IOptions<OpxApiErrorResponseOptions>>().Value.ToString());
	}

	private static TestOpxApiController CreateController(IServiceProvider? services = null)
	{
		var httpContext = new DefaultHttpContext();
		httpContext.RequestServices = services ?? DefaultServices;
		httpContext.Items["StartTime"] = DateTime.UtcNow;
		httpContext.Response.Body = new MemoryStream();

		return new TestOpxApiController
		{
			ControllerContext = new ControllerContext
			{
				HttpContext = httpContext
			}
		};
	}

	private static async Task<JsonElement> ReadResponseAsync(HttpContext httpContext)
	{
		httpContext.Response.Body.Position = 0;
		using var document = await JsonDocument.ParseAsync(httpContext.Response.Body);
		return document.RootElement.Clone();
	}

	private sealed class TestOpxApiController : OpxApiController
	{
		public Task WriteOkAsync(object? data)
		{
			return OkAsync(data);
		}

		public Task WriteOkOrFailAsync(AppResult result)
		{
			return OkOrFailAsync(result);
		}
	}
}
