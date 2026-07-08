// Copyright (c) 2026 - opx
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Opx.Api.Web.Options;

namespace Opx.Api.Web.Docs;

internal sealed class OpxApiDocsGeneratorHostedService : IHostedService
{
	private readonly EndpointDataSource _endpointDataSource;
	private readonly IWebHostEnvironment _environment;
	private readonly IHostApplicationLifetime _hostApplicationLifetime;
	private readonly ILogger<OpxApiDocsGeneratorHostedService> _logger;
	private readonly OpxWebApiOptions _options;

	public OpxApiDocsGeneratorHostedService(
		EndpointDataSource endpointDataSource,
		IWebHostEnvironment environment,
		IHostApplicationLifetime hostApplicationLifetime,
		ILogger<OpxApiDocsGeneratorHostedService> logger,
		OpxWebApiOptions options)
	{
		_endpointDataSource = endpointDataSource;
		_environment = environment;
		_hostApplicationLifetime = hostApplicationLifetime;
		_logger = logger;
		_options = options;
	}

	public Task StartAsync(CancellationToken cancellationToken)
	{
		if (!_options.Docs.Enabled)
		{
			return Task.CompletedTask;
		}

		_hostApplicationLifetime.ApplicationStarted.Register(() =>
		{
			OpxApiDocsGenerator.Generate(_endpointDataSource, _environment.ContentRootPath, _options.Docs);
			_logger.LogInformation("Opx API docs generated to {OutputDirectory}", _options.Docs.OutputDirectory);
		});

		return Task.CompletedTask;
	}

	public Task StopAsync(CancellationToken cancellationToken)
	{
		return Task.CompletedTask;
	}
}
