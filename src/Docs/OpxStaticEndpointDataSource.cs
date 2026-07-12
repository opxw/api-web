// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Primitives;

namespace Opx.Api.Web.Docs;

internal sealed class OpxStaticEndpointDataSource : EndpointDataSource
{
	private readonly IReadOnlyList<Endpoint> _endpoints;

	public OpxStaticEndpointDataSource(IEnumerable<EndpointDataSource> endpointDataSources)
	{
		_endpoints = endpointDataSources
			.SelectMany(endpointDataSource => endpointDataSource.Endpoints)
			.ToList();
	}

	public override IReadOnlyList<Endpoint> Endpoints => _endpoints;

	public override IChangeToken GetChangeToken()
	{
		return new CancellationChangeToken(CancellationToken.None);
	}
}
