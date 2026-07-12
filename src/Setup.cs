// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Opx.Api.Web.Common;
using Opx.Api.Web.Controllers;
using Opx.Api.Web.Docs;
using Opx.Api.Web.Jwt;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Middlewares;
using Opx.Api.Web.Options;
using System.Text;

namespace Opx.Api.Web
{
	public static class SetupExtension
	{
		public static IServiceCollection AddOpxApiWeb(this IServiceCollection services, IConfiguration configuration, Action<OpxWebApiOptions>? configure = null)
		{
			services.AddSingleton(configuration);
			return services.UseOpxWebApi(configure);
		}

		public static IServiceCollection UseOpxWebApi(this IServiceCollection services, Action<OpxWebApiOptions>? configure = null)
		{
			var options = new OpxWebApiOptions();
			configure?.Invoke(options);

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
			return app.UseMiddleware<OpxSecurityHeadersMiddleware>();
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
			return app.UseMiddleware<OpxAccessLogMiddleware>();
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
	}
}
