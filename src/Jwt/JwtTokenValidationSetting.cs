// Copyright (c) 2026 - opx
using Microsoft.IdentityModel.Tokens;

namespace Opx.Api.Web.Jwt
{
	public class JwtTokenValidationSetting : IJwtTokenValidationSetting
	{
		public string SecretKey { get; set; } = "";
		public string Issuer { get; set; } = "";
		public string Audience { get; set; } = "";
		public int ExpirationSeconds { get; set; } = 900;
		public string Algorithm { get; set; } = SecurityAlgorithms.HmacSha256;
		public bool RequireExpirationTime { get; set; } = true;
		public int ClockSkewSeconds { get; set; } = 30;
		public bool RequireHttpsMetadata { get; set; } = true;
	}
}
