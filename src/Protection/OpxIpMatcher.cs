// Copyright (c) 2026 - opx
using System.Net;
using System.Net.Sockets;

namespace Opx.Api.Web.Protection;

public sealed class OpxIpMatcher
{
	private readonly IPAddress[] _addresses;
	private readonly OpxIpNetwork[] _networks;

	private OpxIpMatcher(IPAddress[] addresses, OpxIpNetwork[] networks)
	{
		_addresses = addresses;
		_networks = networks;
	}

	public bool IsMatch(string value)
	{
		if (!IPAddress.TryParse(value, out var address))
		{
			return false;
		}

		return IsMatch(address);
	}

	public bool IsMatch(IPAddress address)
	{
		return _addresses.Any(candidate => candidate.Equals(address))
			|| _networks.Any(network => network.Contains(address));
	}

	public static OpxIpMatcher Create(IEnumerable<string> values)
	{
		var addresses = new List<IPAddress>();
		var networks = new List<OpxIpNetwork>();

		foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
		{
			if (value.Contains('/', StringComparison.Ordinal))
			{
				networks.Add(OpxIpNetwork.Parse(value));
				continue;
			}

			if (!IPAddress.TryParse(value, out var address))
			{
				throw new FormatException($"Invalid IP address '{value}'.");
			}

			addresses.Add(address);
		}

		return new OpxIpMatcher(addresses.ToArray(), networks.ToArray());
	}
}

public sealed class OpxIpNetwork
{
	private readonly IPAddress _network;
	private readonly int _prefixLength;

	private OpxIpNetwork(IPAddress network, int prefixLength)
	{
		_network = network;
		_prefixLength = prefixLength;
	}

	public bool Contains(IPAddress address)
	{
		if (address.AddressFamily != _network.AddressFamily)
		{
			return false;
		}

		var addressBytes = address.GetAddressBytes();
		var networkBytes = _network.GetAddressBytes();
		var fullBytes = _prefixLength / 8;
		var remainingBits = _prefixLength % 8;

		for (var index = 0; index < fullBytes; index++)
		{
			if (addressBytes[index] != networkBytes[index])
			{
				return false;
			}
		}

		if (remainingBits == 0)
		{
			return true;
		}

		var mask = (byte)(0xFF << (8 - remainingBits));
		return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
	}

	public static OpxIpNetwork Parse(string value)
	{
		var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
		if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || !int.TryParse(parts[1], out var prefixLength))
		{
			throw new FormatException($"Invalid CIDR '{value}'.");
		}

		var maxPrefixLength = address.AddressFamily switch
		{
			AddressFamily.InterNetwork => 32,
			AddressFamily.InterNetworkV6 => 128,
			_ => throw new FormatException($"Unsupported IP address family for CIDR '{value}'.")
		};

		if (prefixLength < 0 || prefixLength > maxPrefixLength)
		{
			throw new FormatException($"CIDR '{value}' prefix length must be between 0 and {maxPrefixLength}.");
		}

		return new OpxIpNetwork(address, prefixLength);
	}
}
