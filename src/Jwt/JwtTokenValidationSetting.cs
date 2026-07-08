// Copyright (c) 2026 - opx
namespace Opx.Api.Web.Jwt
{
	public class JwtTokenValidationSetting : IJwtTokenValidationSetting
	{
		public string SecretKey { get; set; }
		public string Issuer { get; set; }
		public string Audience { get; set; }
		public int ExpirationSeconds { get; set; }
		public string Algorithm { get; set; }
	}
}