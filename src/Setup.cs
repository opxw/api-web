using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Opx.Api.Web.Common;
using Opx.Api.Web.Jwt;
using Opx.Api.Web.Middlewares;
using System.Text;

namespace Opx.Api.Web
{
	public static class SetupExtension
	{
		public static IServiceCollection UseOpxWebApi(this IServiceCollection services)
		{
			services.Configure<ApiBehaviorOptions>(o =>
			{
				o.SuppressModelStateInvalidFilter = true;
			});

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
