// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Opx.Api.Web.Common;
using Opx.Api.Web.Controllers;
using Opx.Api.Web.Docs;
using Opx.Api.Web.Jwt;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Middlewares;
using Opx.Api.Web.Options;
using Opx.Web.Framework;
using Opx.Web.Framework.Options;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Opx.Api.Web
{
	public static class SetupExtension
	{
		private static readonly ConditionalWeakTable<WebApplication, object> MappedWebFrameworkApplications = new();
		private static readonly ConditionalWeakTable<WebApplication, object> MappedEndpointProxyApplications = new();

		public static IServiceCollection AddOpxApiWeb(this IServiceCollection services, IConfiguration configuration, Action<OpxWebApiOptions>? configure = null)
		{
			services.AddSingleton(configuration);
			services.AddOpxWebFramework(configuration, options => ConfigureWebFrameworkFromApiProtection(configuration, options));
			return services.UseOpxWebApi(configure);
		}

		public static IServiceCollection UseOpxWebApi(this IServiceCollection services, Action<OpxWebApiOptions>? configure = null)
		{
			var options = new OpxWebApiOptions();
			configure?.Invoke(options);

			services.AddOpxWebFramework();
			services.AddAuthorization();

			services.Configure<ApiBehaviorOptions>(o =>
			{
				o.SuppressModelStateInvalidFilter = true;
			});
			services.AddControllers().AddApplicationPart(typeof(OpxLogsController).Assembly);

			services.AddSingleton(options);
			services.AddSingleton<OpxLogFileReader>();

			if (options.Docs.Enabled)
			{
				services.AddHostedService<OpxApiDocsGeneratorHostedService>();
			}

			return services;
		}

		public static void UseOpxWebApiHandler(this WebApplication webApplication)
		{
			MapOpxWebFrameworkOnce(webApplication);
			webApplication.MapOpxEndpointProxy();

			webApplication.Use(async (context, next) =>
			{
				context.Items["StartTime"] = DateTime.UtcNow;

				await next();
				await webApplication.HandleUncatchedStatusCodeAsync(context);
			});
		}

		public static void UseOpxWebApiStatusCodePages(this WebApplication webApplication)
		{
			webApplication.UseStatusCodePages(async context =>
			{
				await webApplication.HandleUncatchedStatusCodeAsync(context.HttpContext, "StatusCodePages");
			});
		}

		public static IApplicationBuilder UseOpxEndpointLog(this IApplicationBuilder app)
		{
			return app.UseMiddleware<OpxEndpointLogMiddleware>();
		}

		public static IApplicationBuilder UseOpxSecurityHeaders(this IApplicationBuilder app)
		{
			return OpxWebFrameworkExtensions.UseOpxResponseHeaders(app);
		}

		public static IApplicationBuilder UseOpxRateLimiting(this IApplicationBuilder app)
		{
			return app.UseMiddleware<OpxRateLimitingMiddleware>();
		}

		public static IApplicationBuilder UseOpxSuspiciousTrafficGuard(this IApplicationBuilder app)
		{
			return app.UseMiddleware<OpxSuspiciousTrafficGuardMiddleware>();
		}

		public static IApplicationBuilder UseOpxAuthorizationGuard(this IApplicationBuilder app)
		{
			return app.UseMiddleware<OpxAuthorizationGuardMiddleware>();
		}

		public static IApplicationBuilder UseOpxAccessLog(this IApplicationBuilder app)
		{
			return OpxWebFrameworkExtensions.UseOpxAccessLog(app);
		}

		public static IApplicationBuilder UseOpxApiProtection(this IApplicationBuilder app)
		{
			app.UseOpxSecurityHeaders();
			app.UseOpxRateLimiting();
			app.UseOpxSuspiciousTrafficGuard();
			app.UseOpxAuthorizationGuard();
			app.UseOpxAccessLog();

			return app;
		}

		public static OpxApiDocument GenerateOpxApiDocs(this WebApplication app, Action<OpxApiDocsOptions>? configure = null)
		{
			var options = new OpxApiDocsOptions
			{
				Enabled = true
			};
			configure?.Invoke(options);

			var endpointDataSource = new OpxStaticEndpointDataSource(((IEndpointRouteBuilder)app).DataSources);
			var environment = app.Services.GetRequiredService<IWebHostEnvironment>();

			return OpxApiDocsGenerator.Generate(endpointDataSource, environment.ContentRootPath, options);
		}

		public static WebApplication MapOpxEndpointProxy(this WebApplication webApplication)
		{
			if (MappedEndpointProxyApplications.TryGetValue(webApplication, out _))
			{
				return webApplication;
			}

			var configuration = webApplication.Services.GetRequiredService<IConfiguration>();
			var settings = ReadEndpointProxySettings(configuration);
			if (!settings.Enabled)
			{
				MappedEndpointProxyApplications.Add(webApplication, new object());
				return webApplication;
			}

			var rewriteEndpointCache = new ConcurrentDictionary<string, RouteEndpoint?>(StringComparer.OrdinalIgnoreCase);
			foreach (var route in settings.Routes)
			{
				if (!IsLocalPath(route.Key) || !IsLocalPath(route.Value))
				{
					continue;
				}

				var alias = route.Key;
				var target = route.Value;
				var builder = webApplication.MapGet(alias, async (HttpContext context) =>
				{
					if (!await IsEndpointProxyAuthorizedAsync(context, settings))
					{
						await WriteEndpointProxyUnauthorizedAsync(context, alias);
						return;
					}

					if (settings.Mode.Equals("Rewrite", StringComparison.OrdinalIgnoreCase))
					{
						await ExecuteEndpointProxyRewriteAsync(context, target, rewriteEndpointCache);
						return;
					}

					context.Response.Redirect(JoinTargetAndQuery(target, context.Request.QueryString), permanent: false);
				});

				if (settings.RequireAuthorization)
				{
					builder.RequireAuthorization();
				}
			}

			MappedEndpointProxyApplications.Add(webApplication, new object());
			return webApplication;
		}

		public static IServiceCollection UseOpxJwtBearerTokenAuth(this IServiceCollection services, JwtTokenValidationSetting validationSetting)
		{
			services.AddSingleton<IJwtTokenValidationSetting, JwtTokenValidationSetting>(_ => validationSetting);

			var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(validationSetting.SecretKey));
			var validationParameters = new TokenValidationParameters()
			{
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = signingKey,
				ValidateIssuer = string.IsNullOrWhiteSpace(validationSetting.Issuer) ? false : true,
				ValidIssuer = validationSetting.Issuer,
				ValidateAudience = string.IsNullOrWhiteSpace(validationSetting.Audience) ? false : true,
				ValidAudience = validationSetting.Audience,
				ValidateLifetime = true,
				ClockSkew = TimeSpan.Zero,
				RequireExpirationTime = false
			};

			services.AddAuthentication(o =>
			{
				o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
				o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
				o.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
			}).AddJwtBearer(o =>
			{
				o.RequireHttpsMetadata = false;
				o.TokenValidationParameters = validationParameters;
				o.Events = new JwtBearerEvents
				{
					OnAuthenticationFailed = context =>
					{
						return Task.CompletedTask;
					},
					OnTokenValidated = context =>
					{
						return Task.CompletedTask;
					}
				};
			});

			return services;
		}

		private static void ConfigureWebFrameworkFromApiProtection(IConfiguration configuration, OpxWebFrameworkOptions options)
		{
			options.ResponseHeaders.Enabled = configuration.GetValue("OpxApiProtection:SecurityHeaders:Enabled", options.ResponseHeaders.Enabled);
			options.ResponseHeaders.Set["Referrer-Policy"] = configuration.GetValue("OpxApiProtection:SecurityHeaders:ReferrerPolicy", options.ResponseHeaders.Set["Referrer-Policy"]);
			options.ResponseHeaders.Set["X-Frame-Options"] = configuration.GetValue("OpxApiProtection:SecurityHeaders:FrameOptions", options.ResponseHeaders.Set["X-Frame-Options"]);

			options.AccessLog.Enabled = configuration.GetValue("OpxApiProtection:AccessLog:Enabled", options.AccessLog.Enabled);
			options.AccessLog.Output = ParseLogOutput(configuration.GetValue("OpxApiProtection:AccessLog:Output", options.AccessLog.Output.ToString()));
			options.AccessLog.FilePath = configuration.GetValue("OpxApiProtection:AccessLog:FilePath", options.AccessLog.FilePath);

			options.LogAccess.Enabled = configuration.GetValue("OpxApiProtection:LogApi:Enabled", options.LogAccess.Enabled);
			options.LogAccess.RoutePrefix = configuration.GetValue("OpxApiProtection:LogApi:RoutePrefix", options.LogAccess.RoutePrefix);
			options.LogAccess.RequireAuthorization = configuration.GetValue("OpxApiProtection:LogApi:RequireAuthorization", options.LogAccess.RequireAuthorization);
			options.LogAccess.AccessLogId = configuration.GetValue("OpxApiProtection:LogApi:AccessLogId", options.LogAccess.AccessLogId);
			options.LogAccess.SecurityLogId = configuration.GetValue("OpxApiProtection:LogApi:SecurityLogId", options.LogAccess.SecurityLogId);
		}

		private static OpxLogOutput ParseLogOutput(string? value)
		{
			return Enum.TryParse<OpxLogOutput>(value, true, out var output)
				? output
				: OpxLogOutput.Logger;
		}

		private static void MapOpxWebFrameworkOnce(WebApplication webApplication)
		{
			if (MappedWebFrameworkApplications.TryGetValue(webApplication, out _))
			{
				return;
			}

			webApplication.MapOpxWebFramework();
			MappedWebFrameworkApplications.Add(webApplication, new object());
		}

		private static bool IsLocalPath(string? value)
		{
			return !string.IsNullOrWhiteSpace(value)
				&& value.StartsWith("/", StringComparison.Ordinal)
				&& !value.StartsWith("//", StringComparison.Ordinal)
				&& !value.Contains("://", StringComparison.Ordinal);
		}

		private static string JoinTargetAndQuery(string target, QueryString queryString)
		{
			if (!queryString.HasValue)
			{
				return target;
			}

			return target.Contains('?')
				? $"{target}&{queryString.Value.TrimStart('?')}"
				: $"{target}{queryString}";
		}

		private static EndpointProxySettings ReadEndpointProxySettings(IConfiguration configuration)
		{
			var section = configuration.GetSection("OpxApiProtection:EndpointProxy");
			return new EndpointProxySettings(
				section.GetValue("Enabled", false),
				section.GetValue("Mode", "Redirect") ?? "Redirect",
				section.GetValue("RequireAuthorization", false),
				section.GetValue<string>("ApiKey"),
				section.GetValue("ApiKeyHeaderName", "X-Opx-Proxy-Key") ?? "X-Opx-Proxy-Key",
				section.GetSection("Routes").Get<Dictionary<string, string>>() ?? []);
		}

		private static async Task<bool> IsEndpointProxyAuthorizedAsync(HttpContext context, EndpointProxySettings settings)
		{
			if (settings.RequireAuthorization && context.User.Identity?.IsAuthenticated != true)
			{
				return false;
			}

			if (string.IsNullOrWhiteSpace(settings.ApiKey))
			{
				return true;
			}

			if (!context.Request.Headers.TryGetValue(settings.ApiKeyHeaderName, out var value))
			{
				return false;
			}

			return FixedTimeEquals(value.ToString(), settings.ApiKey);
		}

		private static async Task WriteEndpointProxyUnauthorizedAsync(HttpContext context, string alias)
		{
			await ApiResponseObjectValue.ShowErrorResponseAsync(context, StatusCodes.Status401Unauthorized, new ApiErrorValue
			{
				Message = "Unauthorized",
				Id = "EndpointProxy",
				ObjectName = alias
			});
		}

		private static async Task ExecuteEndpointProxyRewriteAsync(HttpContext context, string target, ConcurrentDictionary<string, RouteEndpoint?> endpointCache)
		{
			var originalPath = context.Request.Path;
			var originalQueryString = context.Request.QueryString;
			var targetPath = target;
			var targetQueryString = QueryString.Empty;

			var queryStart = target.IndexOf('?');
			if (queryStart >= 0)
			{
				targetPath = target[..queryStart];
				targetQueryString = QueryString.FromUriComponent(target[queryStart..]);
			}

			var endpoint = endpointCache.GetOrAdd(targetPath, static (path, httpContext) => httpContext.RequestServices
				.GetServices<EndpointDataSource>()
				.SelectMany(source => source.Endpoints)
				.OfType<RouteEndpoint>()
				.FirstOrDefault(candidate => EndpointPathMatches(candidate.RoutePattern.RawText, path)), context);

			if (endpoint?.RequestDelegate is null)
			{
				context.Response.StatusCode = StatusCodes.Status404NotFound;
				return;
			}

			if (!await IsTargetEndpointAuthorizedAsync(context, endpoint))
			{
				await WriteEndpointProxyUnauthorizedAsync(context, originalPath.ToString());
				return;
			}

			context.Items["OpxEndpointProxyAlias"] = originalPath.ToString();
			context.Items["OpxEndpointProxyTarget"] = targetPath;
			context.Request.Path = targetPath;
			context.Request.QueryString = MergeQueryStrings(targetQueryString, originalQueryString);
			context.SetEndpoint(endpoint);

			await endpoint.RequestDelegate(context);
		}

		private static async Task<bool> IsTargetEndpointAuthorizedAsync(HttpContext context, Endpoint endpoint)
		{
			if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
			{
				return true;
			}

			var authorizeData = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
			if (authorizeData.Count == 0)
			{
				return true;
			}

			var policyProvider = context.RequestServices.GetService<IAuthorizationPolicyProvider>();
			var authorizationService = context.RequestServices.GetService<IAuthorizationService>();
			if (policyProvider is null || authorizationService is null)
			{
				return false;
			}

			var policy = await AuthorizationPolicy.CombineAsync(policyProvider, authorizeData);
			if (policy is null)
			{
				return true;
			}

			var result = await authorizationService.AuthorizeAsync(context.User, context, policy);
			return result.Succeeded;
		}

		private static QueryString MergeQueryStrings(QueryString target, QueryString original)
		{
			if (!target.HasValue)
			{
				return original;
			}

			if (!original.HasValue)
			{
				return target;
			}

			return QueryString.FromUriComponent($"{target.Value}&{original.Value.TrimStart('?')}");
		}

		private static bool EndpointPathMatches(string? routePattern, string targetPath)
		{
			if (string.IsNullOrWhiteSpace(routePattern))
			{
				return false;
			}

			return string.Equals(routePattern.TrimStart('/'), targetPath.TrimStart('/'), StringComparison.OrdinalIgnoreCase);
		}

		private static bool FixedTimeEquals(string value, string expected)
		{
			var valueHash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
			var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
			return CryptographicOperations.FixedTimeEquals(valueHash, expectedHash);
		}

		private sealed record EndpointProxySettings(
			bool Enabled,
			string Mode,
			bool RequireAuthorization,
			string? ApiKey,
			string ApiKeyHeaderName,
			Dictionary<string, string> Routes);
	}
}
