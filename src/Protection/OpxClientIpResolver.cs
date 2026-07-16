// Copyright (c) 2026 - opx
using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Primitives;

namespace Opx.Api.Web.Protection;

public readonly record struct OpxClientIpResolution(
	string Text,
	IPAddress? Address,
	string Source,
	string PeerText,
	IPAddress? PeerAddress);

public static class OpxClientIpResolver
{
	private static readonly string[] DefaultHeaderNames = ["X-Forwarded-For", "X-Real-IP"];
	private static readonly string[] DefaultTrustedProxies = ["127.0.0.1", "::1"];
	private static readonly ConditionalWeakTable<IConfiguration, ClientIpSettingsCache> SettingsCaches = new();

	public static (string Text, IPAddress? Address) Resolve(HttpContext context, IConfiguration? configuration = null)
	{
		var result = ResolveCore(context, configuration);
		return ToResult(result.Address);
	}

	public static OpxClientIpResolution ResolveDetails(HttpContext context, IConfiguration? configuration = null)
	{
		var result = ResolveCore(context, configuration);
		var resolved = ToResult(result.Address);
		var peer = ToResult(result.PeerAddress);
		return new OpxClientIpResolution(resolved.Text, resolved.Address, result.Source, peer.Text, peer.Address);
	}

	private static (IPAddress? Address, string Source, IPAddress? PeerAddress) ResolveCore(HttpContext context, IConfiguration? configuration)
	{
		ArgumentNullException.ThrowIfNull(context);
		var peerAddress = Normalize(context.Connection.RemoteIpAddress);
		if (configuration is null)
		{
			return (peerAddress, "RemoteIpAddress", peerAddress);
		}

		var settings = SettingsCaches.GetValue(configuration, static value => new ClientIpSettingsCache(value)).Get();
		if (!settings.TrustForwardedHeaders
			|| peerAddress is null
			|| (!settings.TrustAnyProxy && !settings.TrustedPeers.IsMatch(peerAddress)))
		{
			return (peerAddress, "RemoteIpAddress", peerAddress);
		}

		foreach (var headerName in settings.HeaderNames)
		{
			if (!context.Request.Headers.TryGetValue(headerName, out var headerValue)
				|| string.IsNullOrWhiteSpace(headerValue))
			{
				continue;
			}

			var rawValue = headerValue.ToString();
			if (rawValue.Length > settings.MaxHeaderValueLength)
			{
				continue;
			}

			var address = IsForwardedChainHeader(headerName)
				? ResolveForwardedChain(rawValue, settings)
				: ParseAddress(rawValue);
			if (address is not null)
			{
				return (address, headerName, peerAddress);
			}
		}

		return (peerAddress, "RemoteIpAddress", peerAddress);
	}

	private static IPAddress? ResolveForwardedChain(string value, ClientIpSettings settings)
	{
		var remaining = value.AsSpan();
		var processed = 0;
		while (!remaining.IsEmpty && processed < settings.MaxForwardedEntries)
		{
			var separator = remaining.LastIndexOf(',');
			var candidate = separator < 0 ? remaining : remaining[(separator + 1)..];
			remaining = separator < 0 ? [] : remaining[..separator];
			processed++;

			var address = ParseAddress(candidate);
			if (address is null)
			{
				return null;
			}

			if (settings.TrustAnyProxy || !settings.TrustedPeers.IsMatch(address))
			{
				return address;
			}
		}

		return null;
	}

	private static IPAddress? ParseAddress(string value) => ParseAddress(value.AsSpan());

	private static IPAddress? ParseAddress(ReadOnlySpan<char> value)
	{
		value = value.Trim();
		if (value.Length > 1 && value[0] == '"' && value[^1] == '"')
		{
			value = value[1..^1].Trim();
		}

		if (IPAddress.TryParse(value, out var address))
		{
			return Normalize(address);
		}

		return IPEndPoint.TryParse(value, out var endpoint) ? Normalize(endpoint.Address) : null;
	}

	private static IPAddress? Normalize(IPAddress? address)
	{
		return address?.IsIPv4MappedToIPv6 == true ? address.MapToIPv4() : address;
	}

	private static (string Text, IPAddress? Address) ToResult(IPAddress? address)
	{
		return address is null ? ("unknown", null) : (address.ToString(), address);
	}

	private static bool IsForwardedChainHeader(string headerName)
	{
		return headerName.Equals("X-Forwarded-For", StringComparison.OrdinalIgnoreCase)
			|| headerName.Equals("X-Original-Forwarded-For", StringComparison.OrdinalIgnoreCase);
	}

	private sealed class ClientIpSettingsCache
	{
		private readonly IConfiguration _configuration;
		private readonly object _lock = new();
		private IChangeToken? _changeToken;
		private ClientIpSettings? _settings;

		public ClientIpSettingsCache(IConfiguration configuration)
		{
			_configuration = configuration;
		}

		public ClientIpSettings Get()
		{
			var currentToken = _configuration.GetReloadToken();
			if (_settings is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
			{
				return _settings;
			}

			lock (_lock)
			{
				currentToken = _configuration.GetReloadToken();
				if (_settings is not null && ReferenceEquals(_changeToken, currentToken) && !currentToken.HasChanged)
				{
					return _settings;
				}

				_settings = ReadSettings(_configuration);
				_changeToken = currentToken;
				return _settings;
			}
		}
	}

	private static ClientIpSettings ReadSettings(IConfiguration configuration)
	{
		var configuredHeaderNames = ReadValues(configuration,
			"OpxApiProtection:ClientIp:HeaderNames",
			"OpxApiProtection:ForwardedHeaders:ClientIpHeaders",
			"OpxApiProtection:ForwardedHeaders:HeaderNames")
			.Concat(new[]
			{
				configuration.GetValue<string>("OpxApiProtection:ClientIp:HeaderName"),
				configuration.GetValue<string>("OpxApiProtection:Forwarder:RealIpHeader"),
				configuration.GetValue<string>("OpxApiProtection:Forwarder:HeaderName"),
				configuration.GetValue<string>("OpxApiProtection:ForwarderHeader")
			})
			.Where(value => !string.IsNullOrWhiteSpace(value))
			.Select(value => value!.Trim())
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.ToArray();
		var headerNames = configuredHeaderNames
			.Where(IsValidHeaderName)
			.Take(16)
			.ToArray();
		if (configuredHeaderNames.Length == 0)
		{
			headerNames = DefaultHeaderNames;
		}

		var trustedValues = ReadValues(configuration,
			"OpxApiProtection:ClientIp:TrustedProxies",
			"OpxApiProtection:ClientIp:TrustedNetworks",
			"OpxApiProtection:ForwardedHeaders:KnownProxies",
			"OpxApiProtection:ForwardedHeaders:KnownNetworks")
			.Concat(new[]
			{
				configuration.GetValue<string>("OpxApiProtection:ClientIp:TrustedProxy"),
				configuration.GetValue<string>("OpxApiProtection:ClientIp:TrustedNetwork")
			})
			.Where(value => !string.IsNullOrWhiteSpace(value))
			.Select(value => value!.Trim())
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.ToArray();
		if (trustedValues.Length == 0)
		{
			trustedValues = DefaultTrustedProxies;
		}

		return new ClientIpSettings(
			configuration.GetValue("OpxApiProtection:ClientIp:TrustForwardedHeaders", false),
			configuration.GetValue("OpxApiProtection:ClientIp:TrustAnyProxy", false),
			headerNames,
			CreateMatcherIgnoringInvalidValues(trustedValues),
			Math.Clamp(configuration.GetValue("OpxApiProtection:ClientIp:MaxForwardedEntries", 10), 1, 100),
			Math.Clamp(configuration.GetValue("OpxApiProtection:ClientIp:MaxHeaderValueLength", 4096), 64, 32768));
	}

	private static IEnumerable<string> ReadValues(IConfiguration configuration, params string[] keys)
	{
		return keys
			.Select(key => configuration.GetSection(key).Get<string[]>())
			.Where(values => values is not null)
			.SelectMany(values => values!)
			.Where(value => !string.IsNullOrWhiteSpace(value))
			.Select(value => value.Trim())
			.Distinct(StringComparer.OrdinalIgnoreCase);
	}

	private static OpxIpMatcher CreateMatcherIgnoringInvalidValues(IEnumerable<string> values)
	{
		var validValues = new List<string>();
		foreach (var value in values)
		{
			try
			{
				_ = OpxIpMatcher.Create([value]);
				validValues.Add(value);
			}
			catch (FormatException)
			{
			}
		}

		return OpxIpMatcher.Create(validValues);
	}

	private static bool IsValidHeaderName(string value)
	{
		return value.Length is > 0 and <= 128 && value.All(character =>
			char.IsAsciiLetterOrDigit(character)
			|| character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');
	}

	private sealed record ClientIpSettings(
		bool TrustForwardedHeaders,
		bool TrustAnyProxy,
		string[] HeaderNames,
		OpxIpMatcher TrustedPeers,
		int MaxForwardedEntries,
		int MaxHeaderValueLength);
}
