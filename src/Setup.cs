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
using Opx.Web.Framework;
using Opx.Web.Framework.Options;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

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
			services.AddSingleton<OpxEndpointLogWriter>();
			services.AddSingleton<OpxProtectionMetrics>();
			services.AddSingleton<OpxProtectionPolicyProvider>();
			services.AddSingleton<OpxSecurityIssueLogWriter>();
			services.AddHostedService<OpxProtectionConfigurationValidator>();
			services.AddHostedService(provider => provider.GetRequiredService<OpxEndpointLogWriter>());
			services.AddHostedService(provider => provider.GetRequiredService<OpxSecurityIssueLogWriter>());

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

		public static IApplicationBuilder UseOpxApiProtectionFast(this IApplicationBuilder app)
		{
			return app.UseMiddleware<OpxApiProtectionFastMiddleware>();
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
