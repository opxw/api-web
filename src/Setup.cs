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
using Opx.Api.Web.Protection;
using Opx.Api.Web.WebSockets;
using Opx.Web.Framework;
using Opx.Web.Framework.Options;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Opx.Api.Web
{
	public static class SetupExtension
	{
		private const string FrameworkMiddlewareMarkerPrefix = "Opx.Web.Framework.Middleware.";
		private const string ApiMiddlewareMarkerPrefix = "Opx.Api.Web.Middleware.";
		private const string ApiProtectionModeMarker = "Opx.Api.Web.ProtectionMode";
		private static readonly ConditionalWeakTable<WebApplication, object> MappedWebFrameworkApplications = new();
		private static readonly ConditionalWeakTable<WebApplication, object> MappedEndpointProxyApplications = new();
		private static readonly ConditionalWeakTable<WebApplication, object> MappedWebSocketApplications = new();

		public static IServiceCollection AddOpxApiWeb(this IServiceCollection services, IConfiguration configuration, Action<OpxWebApiOptions>? configure = null)
		{
			services.AddSingleton(configuration);
			services.AddOpxApiResponseWriter(configuration);
			services.AddOptions<OpxApiResponseHeaderOptions>()
				.Bind(configuration.GetSection("OpxApiProtection:ResponseHeaders"));
			services.AddOpxWebFramework(configuration, options => ConfigureWebFrameworkFromApiProtection(configuration, options));
			return services.UseOpxWebApi(configure);
		}

		public static IServiceCollection UseOpxWebApi(this IServiceCollection services, Action<OpxWebApiOptions>? configure = null)
		{
			var options = new OpxWebApiOptions();
			configure?.Invoke(options);

			services.AddOpxWebFramework();
			services.AddOptions<OpxApiErrorResponseOptions>();
			services.AddOptions<OpxApiResponseHeaderOptions>();
			services.AddAuthorization();

			services.Configure<ApiBehaviorOptions>(o =>
			{
				o.SuppressModelStateInvalidFilter = true;
			});
			services.AddControllers().AddApplicationPart(typeof(OpxLogsController).Assembly);

			services.AddSingleton(options);
			services.AddSingleton<OpxLogFileReader>();
			services.AddSingleton<OpxEndpointLogWriter>();
			services.AddSingleton<OpxProtectionMetrics>();
			services.AddSingleton<OpxProtectionPolicyProvider>();
			services.AddSingleton<OpxSecurityIssueLogWriter>();
			services.AddOpxWebSocket();
			services.AddHostedService<OpxProtectionConfigurationValidator>();
			services.AddHostedService(provider => provider.GetRequiredService<OpxEndpointLogWriter>());
			services.AddHostedService(provider => provider.GetRequiredService<OpxSecurityIssueLogWriter>());

			if (options.Docs.Enabled)
			{
				services.AddHostedService<OpxApiDocsGeneratorHostedService>();
			}

			return services;
		}

		public static IServiceCollection AddOpxApiResponseWriter(
			this IServiceCollection services,
			IConfiguration configuration)
		{
			services.AddOptions<OpxApiErrorResponseOptions>()
				.Bind(configuration.GetSection("OpxApiProtection:ErrorResponse"))
				.Validate(
					options => Enum.IsDefined(options.HttpStatusMode),
					"OpxApiProtection:ErrorResponse:HttpStatusMode must be Always200 or Original.")
				.ValidateOnStart();
			return services;
		}

		public static void UseOpxWebApiHandler(this WebApplication webApplication)
		{
			webApplication.UseOpxWebSocket();
			webApplication.MapOpxWebSocket();
			MapOpxWebFrameworkOnce(webApplication);
			webApplication.MapOpxEndpointProxy();

			webApplication.Use(async (context, next) =>
			{
				context.Items["StartTime"] = DateTime.UtcNow;

				await next();
				await webApplication.HandleUncatchedStatusCodeAsync(context);
			});
		}

		public static IServiceCollection AddOpxWebSocket(this IServiceCollection services, Action<OpxWebSocketOptions>? configure = null)
		{
			var optionsBuilder = services.AddOptions<OpxWebSocketOptions>()
				.BindConfiguration("OpxApiProtection:WebSocket");
			if (configure is not null)
			{
				optionsBuilder.Configure(configure);
			}

			services.TryAddScoped<IOpxWebSocketHandler, OpxNoOpWebSocketHandler>();
			services.TryAddScoped<OpxWebSocketMessageRouter>();
			services.TryAddSingleton<OpxWebSocketConnectionManager>();
			services.TryAddEnumerable(ServiceDescriptor.Scoped<IOpxWebSocketMessageHandler, OpxNoOpWebSocketMessageHandler>());
			services.TryAddSingleton<OpxRedisWebSocketBackplane>();
			services.TryAddSingleton<IOpxWebSocketBackplane>(provider => provider.GetRequiredService<OpxRedisWebSocketBackplane>());
			services.TryAddSingleton<IOpxWebSocketConnectionManager>(provider => provider.GetRequiredService<OpxWebSocketConnectionManager>());
			services.TryAddSingleton<OpxWebSocketEndpoint>();
			services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, OpxWebSocketLifetimeService>());
			services.AddHostedService(provider => provider.GetRequiredService<OpxRedisWebSocketBackplane>());
			return services;
		}

		public static IServiceCollection AddOpxWebSocketMessageHandler<THandler>(this IServiceCollection services)
			where THandler : class, IOpxWebSocketMessageHandler
		{
			services.AddScoped<IOpxWebSocketMessageHandler, THandler>();
			return services;
		}

		public static IServiceCollection AddOpxWebSocket<THandler>(this IServiceCollection services, Action<OpxWebSocketOptions>? configure = null)
			where THandler : class, IOpxWebSocketHandler
		{
			services.AddOpxWebSocket(configure);
			services.Replace(ServiceDescriptor.Scoped<IOpxWebSocketHandler, THandler>());
			return services;
		}

		public static WebApplication UseOpxWebSocket(this WebApplication webApplication)
		{
			var options = webApplication.Services.GetRequiredService<IOptionsMonitor<OpxWebSocketOptions>>().CurrentValue;
			if (!options.Enabled)
			{
				return webApplication;
			}

			var webSocketOptions = new Microsoft.AspNetCore.Builder.WebSocketOptions
			{
				KeepAliveInterval = TimeSpan.FromSeconds(Math.Max(1, options.KeepAliveIntervalSeconds)),
				KeepAliveTimeout = TimeSpan.FromSeconds(Math.Max(1, options.KeepAliveTimeoutSeconds))
			};
			foreach (var origin in (options.AllowedOrigins ?? []).Where(origin => !string.IsNullOrWhiteSpace(origin)))
			{
				webSocketOptions.AllowedOrigins.Add(origin);
			}

			webApplication.UseWebSockets(webSocketOptions);
			return webApplication;
		}

		public static WebApplication MapOpxWebSocket(this WebApplication webApplication)
		{
			if (MappedWebSocketApplications.TryGetValue(webApplication, out _))
			{
				return webApplication;
			}

			var options = webApplication.Services.GetRequiredService<IOptionsMonitor<OpxWebSocketOptions>>().CurrentValue;
			if (!options.Enabled)
			{
				MappedWebSocketApplications.Add(webApplication, new object());
				return webApplication;
			}

			if (string.IsNullOrWhiteSpace(options.Path) || !options.Path.StartsWith("/", StringComparison.Ordinal))
			{
				throw new InvalidOperationException("OpxApiProtection:WebSocket:Path must start with '/'.");
			}

			var endpoint = webApplication.MapMethods(options.Path, ["GET"], async context =>
			{
				await context.RequestServices.GetRequiredService<OpxWebSocketEndpoint>().HandleAsync(context);
			});
			if (options.RequireAuthorization)
			{
				endpoint.RequireAuthorization();
			}

			MappedWebSocketApplications.Add(webApplication, new object());
			return webApplication;
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
			return UseOnce<OpxEndpointLogMiddleware>(app, ApiMiddlewareMarkerPrefix + "EndpointLog");
		}

		public static IApplicationBuilder UseOpxSecurityHeaders(this IApplicationBuilder app)
		{
			return UseFrameworkMiddlewareOnce(
				app,
				FrameworkMiddlewareMarkerPrefix + "ResponseHeaders",
				OpxWebFrameworkExtensions.UseOpxResponseHeaders);
		}

		public static IApplicationBuilder UseOpxRateLimiting(this IApplicationBuilder app)
		{
			return UseOnce<OpxRateLimitingMiddleware>(app, ApiMiddlewareMarkerPrefix + "RateLimiting");
		}

		public static IApplicationBuilder UseOpxSuspiciousTrafficGuard(this IApplicationBuilder app)
		{
			return UseOnce<OpxSuspiciousTrafficGuardMiddleware>(app, ApiMiddlewareMarkerPrefix + "SuspiciousTraffic");
		}

		public static IApplicationBuilder UseOpxAuthorizationGuard(this IApplicationBuilder app)
		{
			return UseOnce<OpxAuthorizationGuardMiddleware>(app, ApiMiddlewareMarkerPrefix + "AuthorizationGuard");
		}

		public static IApplicationBuilder UseOpxAccessLog(this IApplicationBuilder app)
		{
			return UseFrameworkMiddlewareOnce(
				app,
				FrameworkMiddlewareMarkerPrefix + "AccessLog",
				OpxWebFrameworkExtensions.UseOpxAccessLog);
		}

		public static IApplicationBuilder UseOpxApiProtection(this IApplicationBuilder app)
		{
			EnsureProtectionMode(app, "Normal");
			app.UseOpxSecurityHeaders();
			app.UseOpxRateLimiting();
			app.UseOpxSuspiciousTrafficGuard();
			app.UseOpxAuthorizationGuard();
			app.UseOpxAccessLog();

			return app;
		}

		public static IApplicationBuilder UseOpxApiProtectionFast(this IApplicationBuilder app)
		{
			EnsureProtectionMode(app, "Fast");
			app.UseOpxSecurityHeaders();

			var fastMarker = ApiMiddlewareMarkerPrefix + "ProtectionFast";
			if (app.Properties.ContainsKey(fastMarker))
			{
				return app;
			}

			var individualMarkers = new[]
			{
				ApiMiddlewareMarkerPrefix + "RateLimiting",
				ApiMiddlewareMarkerPrefix + "SuspiciousTraffic",
				ApiMiddlewareMarkerPrefix + "AuthorizationGuard"
			};
			if (individualMarkers.Any(app.Properties.ContainsKey))
			{
				throw new InvalidOperationException("UseOpxApiProtectionFast cannot be combined with individually registered API protection middleware.");
			}

			app.UseMiddleware<OpxApiProtectionFastMiddleware>(false);
			app.Properties[fastMarker] = true;
			foreach (var marker in individualMarkers)
			{
				app.Properties[marker] = true;
			}

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
			var environment = webApplication.Services.GetService<IWebHostEnvironment>();
			var settings = ReadEndpointProxySettings(configuration, environment?.ContentRootPath);
			if (!settings.Enabled)
			{
				MappedEndpointProxyApplications.Add(webApplication, new object());
				return webApplication;
			}

			var rewriteEndpointCache = new ConcurrentDictionary<string, RouteEndpoint?>(StringComparer.OrdinalIgnoreCase);
			var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var route in settings.Routes)
			{
				if (!route.Enabled || !IsValidProxyRoute(route, settings))
				{
					continue;
				}

				if (!aliases.Add(route.Alias))
				{
					if (settings.FailOnConflict)
					{
						throw new InvalidOperationException($"Endpoint proxy alias '{route.Alias}' is duplicated.");
					}

					continue;
				}

				var alias = route.Alias;
				var target = route.Target;
				var methods = route.Methods.Length == 0 ? settings.Methods : route.Methods;
				if (IsEndpointProxyAliasConflictingWithEndpoint(webApplication, alias, methods))
				{
					if (settings.FailOnConflict)
					{
						throw new InvalidOperationException($"Endpoint proxy alias '{alias}' conflicts with an existing endpoint route.");
					}

					continue;
				}

				var builder = webApplication.MapMethods(alias, methods, async (HttpContext context) =>
				{
					context.RequestServices.GetService<OpxProtectionMetrics>()?.IncrementProxyHits();
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

					context.Response.Redirect(JoinTargetAndQuery(ResolveRouteTemplate(target, context.Request.RouteValues), context.Request.QueryString), permanent: false);
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
			if (!configuration.GetValue("OpxApiProtection:ResponseHeaders:ExposeExecutionTime", true)
				&& !options.ResponseHeaders.Remove.Contains("Execution-Time", StringComparer.OrdinalIgnoreCase))
			{
				options.ResponseHeaders.Remove = [.. options.ResponseHeaders.Remove, "Execution-Time"];
			}
			options.ResponseHeaders.Set["Referrer-Policy"] = configuration.GetValue("OpxApiProtection:SecurityHeaders:ReferrerPolicy", options.ResponseHeaders.Set["Referrer-Policy"]);
			options.ResponseHeaders.Set["X-Frame-Options"] = configuration.GetValue("OpxApiProtection:SecurityHeaders:FrameOptions", options.ResponseHeaders.Set["X-Frame-Options"]);

			options.AccessLog.Enabled = configuration.GetValue("OpxApiProtection:AccessLog:Enabled", options.AccessLog.Enabled);
			options.AccessLog.Output = ParseLogOutput(configuration.GetValue("OpxApiProtection:AccessLog:Output", options.AccessLog.Output.ToString()));
			options.AccessLog.FilePath = configuration.GetValue("OpxApiProtection:AccessLog:FilePath", options.AccessLog.FilePath);
			options.AccessLog.IncludeSuspiciousRequests = configuration.GetValue<bool?>("OpxApiProtection:AccessLog:IncludeSuspiciousRequests")
				?? configuration.GetValue("OpxApiProtection:SuspiciousTraffic:IncludeInAccessLog", options.AccessLog.IncludeSuspiciousRequests);

			options.LogAccess.Enabled = configuration.GetValue("OpxApiProtection:LogApi:Enabled", options.LogAccess.Enabled);
			options.LogAccess.RoutePrefix = configuration.GetValue("OpxApiProtection:LogApi:RoutePrefix", options.LogAccess.RoutePrefix);
			options.LogAccess.RequireAuthorization = configuration.GetValue("OpxApiProtection:LogApi:RequireAuthorization", options.LogAccess.RequireAuthorization);
			options.LogAccess.AccessLogId = configuration.GetValue("OpxApiProtection:LogApi:AccessLogId", options.LogAccess.AccessLogId);
			options.LogAccess.SecurityLogId = configuration.GetValue("OpxApiProtection:LogApi:SecurityLogId", options.LogAccess.SecurityLogId);
		}

		private static IApplicationBuilder UseOnce<TMiddleware>(IApplicationBuilder app, string marker)
		{
			if (app.Properties.ContainsKey(marker))
			{
				return app;
			}

			app.UseMiddleware<TMiddleware>();
			app.Properties[marker] = true;
			return app;
		}

		private static IApplicationBuilder UseFrameworkMiddlewareOnce(
			IApplicationBuilder app,
			string marker,
			Func<IApplicationBuilder, IApplicationBuilder> register)
		{
			if (app.Properties.ContainsKey(marker))
			{
				return app;
			}

			register(app);
			app.Properties[marker] = true;
			return app;
		}

		private static void EnsureProtectionMode(IApplicationBuilder app, string mode)
		{
			if (!app.Properties.TryGetValue(ApiProtectionModeMarker, out var configuredMode))
			{
				app.Properties[ApiProtectionModeMarker] = mode;
				return;
			}

			if (!string.Equals(configuredMode?.ToString(), mode, StringComparison.Ordinal))
			{
				throw new InvalidOperationException($"Opx API protection mode '{configuredMode}' is already registered and cannot be combined with '{mode}'.");
			}
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

		private static EndpointProxySettings ReadEndpointProxySettings(IConfiguration configuration, string? contentRootPath)
		{
			var section = configuration.GetSection("OpxEndpointProxy");
			if (!section.Exists())
			{
				section = configuration.GetSection("OpxApiProtection:EndpointProxy");
			}

			var methods = section.GetSection("Methods").Get<string[]>() ?? ["GET"];
			return new EndpointProxySettings(
				section.GetValue("Enabled", false),
				section.GetValue("Mode", "Redirect") ?? "Redirect",
				section.GetValue("RequireAuthorization", false),
				section.GetValue<string>("ApiKey"),
				section.GetValue("ApiKeyHeaderName", "X-Opx-Proxy-Key") ?? "X-Opx-Proxy-Key",
				methods,
				section.GetSection("AllowedAliasPrefixes").Get<string[]>() ?? [],
				section.GetValue("FailOnConflict", true),
				ReadEndpointProxyRoutes(section, methods, contentRootPath));
		}

		private static List<EndpointProxyRoute> ReadEndpointProxyRoutes(IConfigurationSection section, string[] defaultMethods, string? contentRootPath)
		{
			var routes = new List<EndpointProxyRoute>();
			routes.AddRange(ReadEndpointProxyRoutesFromSection(section, defaultMethods));

			var routeMapPath = section.GetValue<string>("RouteMapPath");
			if (string.IsNullOrWhiteSpace(routeMapPath))
			{
				return routes;
			}

			var filePath = Path.IsPathRooted(routeMapPath)
				? routeMapPath
				: Path.Combine(contentRootPath ?? AppContext.BaseDirectory, routeMapPath);

			if (!File.Exists(filePath))
			{
				return routes;
			}

			using var stream = File.OpenRead(filePath);
			var routeMap = JsonSerializer.Deserialize<EndpointProxyRouteMap>(stream, new JsonSerializerOptions
			{
				PropertyNameCaseInsensitive = true
			});

			if (routeMap?.Routes is null)
			{
				return routes;
			}

			routes.AddRange(routeMap.Routes.Select(route => route with
			{
				Methods = route.Methods.Length == 0 ? defaultMethods : route.Methods
			}));

			return routes;
		}

		private static IEnumerable<EndpointProxyRoute> ReadEndpointProxyRoutesFromSection(IConfigurationSection section, string[] defaultMethods)
		{
			var arrayRoutes = section.GetSection("Routes").Get<EndpointProxyRoute[]>();
			if (arrayRoutes is { Length: > 0 })
			{
				return arrayRoutes.Select(route => route with
				{
					Methods = route.Methods.Length == 0 ? defaultMethods : route.Methods
				});
			}

			var dictionaryRoutes = section.GetSection("Routes").Get<Dictionary<string, string>>() ?? [];
			return dictionaryRoutes.Select(route => new EndpointProxyRoute(true, route.Key, route.Value, defaultMethods));
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

			var cacheKey = $"{context.Request.Method}:{targetPath}";
			var endpoint = endpointCache.GetOrAdd(cacheKey, static (key, httpContext) =>
			{
				var separatorIndex = key.IndexOf(':');
				var method = key[..separatorIndex];
				var path = key[(separatorIndex + 1)..];
				return httpContext.RequestServices
					.GetServices<EndpointDataSource>()
					.SelectMany(source => source.Endpoints)
					.OfType<RouteEndpoint>()
					.FirstOrDefault(candidate => EndpointPathMatches(candidate.RoutePattern.RawText, path)
						&& EndpointMethodMatches(candidate, method));
			}, context);

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
			context.Request.Path = ResolveRouteTemplate(targetPath, context.Request.RouteValues);
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

			return string.Equals(NormalizeRoutePattern(routePattern).TrimStart('/'), NormalizeRoutePattern(targetPath).TrimStart('/'), StringComparison.OrdinalIgnoreCase);
		}

		private static bool EndpointMethodMatches(Endpoint endpoint, string method)
		{
			var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods;
			return methods is null || methods.Count == 0 || methods.Any(value => string.Equals(value, method, StringComparison.OrdinalIgnoreCase));
		}

		private static bool IsEndpointProxyAliasConflictingWithEndpoint(IEndpointRouteBuilder routeBuilder, string alias, string[] methods)
		{
			return routeBuilder.DataSources
				.SelectMany(source => source.Endpoints)
				.OfType<RouteEndpoint>()
				.Any(endpoint => EndpointPathMatches(endpoint.RoutePattern.RawText, alias)
					&& methods.Any(method => EndpointMethodMatches(endpoint, method)));
		}

		private static string ResolveRouteTemplate(string template, RouteValueDictionary routeValues)
		{
			var resolved = template;
			foreach (var routeValue in routeValues)
			{
				var value = Uri.EscapeDataString(routeValue.Value?.ToString() ?? string.Empty);
				resolved = Regex.Replace(
					resolved,
					$@"\{{(\*\*|\*)?{Regex.Escape(routeValue.Key)}(:[^}}]+)?\}}",
					value,
					RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
			}

			return resolved;
		}

		private static string NormalizeRoutePattern(string routePattern)
		{
			return Regex.Replace(
				routePattern,
				@"\{(\*\*|\*)?([^}:]+)(:[^}]+)?\}",
				match => $"{{{match.Groups[1].Value}{match.Groups[2].Value}}}",
				RegexOptions.CultureInvariant);
		}

		private static bool FixedTimeEquals(string value, string expected)
		{
			var valueHash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
			var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
			return CryptographicOperations.FixedTimeEquals(valueHash, expectedHash);
		}

		private static bool IsValidProxyRoute(EndpointProxyRoute route, EndpointProxySettings settings)
		{
			if (!IsLocalPath(route.Alias) || !IsLocalPath(route.Target))
			{
				if (settings.FailOnConflict)
				{
					throw new InvalidOperationException($"Endpoint proxy route alias '{route.Alias}' and target '{route.Target}' must be local paths.");
				}

				return false;
			}

			if (settings.AllowedAliasPrefixes.Length > 0
				&& !settings.AllowedAliasPrefixes.Any(prefix => IsLocalPath(prefix) && route.Alias.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
			{
				if (settings.FailOnConflict)
				{
					throw new InvalidOperationException($"Endpoint proxy alias '{route.Alias}' is outside the allowed prefixes: {string.Join(", ", settings.AllowedAliasPrefixes)}.");
				}

				return false;
			}

			return true;
		}

		private sealed record EndpointProxySettings(
			bool Enabled,
			string Mode,
			bool RequireAuthorization,
			string? ApiKey,
			string ApiKeyHeaderName,
			string[] Methods,
			string[] AllowedAliasPrefixes,
			bool FailOnConflict,
			List<EndpointProxyRoute> Routes);

		private sealed record EndpointProxyRoute(
			bool Enabled,
			string Alias,
			string Target,
			string[] Methods)
		{
			public EndpointProxyRoute() : this(true, string.Empty, string.Empty, [])
			{
			}
		}

		private sealed record EndpointProxyRouteMap(List<EndpointProxyRoute> Routes);
	}
}
