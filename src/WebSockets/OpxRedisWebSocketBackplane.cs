// Copyright (c) 2026 - opx
using System.Text.Json;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Opx.Api.Web.WebSockets;

internal sealed class OpxRedisWebSocketBackplane : BackgroundService, IOpxWebSocketBackplane
{
	private readonly ILogger<OpxRedisWebSocketBackplane> _logger;
	private readonly IOptionsMonitor<OpxWebSocketOptions> _options;
	private IConnectionMultiplexer? _connection;
	private Func<OpxWebSocketBackplaneMessage, CancellationToken, ValueTask>? _receiver;

	public OpxRedisWebSocketBackplane(IOptionsMonitor<OpxWebSocketOptions> options, ILogger<OpxRedisWebSocketBackplane> logger)
	{
		_options = options;
		_logger = logger;
	}

	public bool Enabled => _options.CurrentValue.Redis?.Enabled == true;
	public bool IsConnected => _connection?.IsConnected == true;

	public void SetReceiver(Func<OpxWebSocketBackplaneMessage, CancellationToken, ValueTask> receiver)
	{
		_receiver = receiver;
	}

	public async ValueTask PublishAsync(OpxWebSocketBackplaneMessage message, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		var redis = _options.CurrentValue.Redis;
		var connection = _connection;
		if (redis?.Enabled != true || connection?.IsConnected != true)
		{
			return;
		}

		var payload = JsonSerializer.Serialize(message, OpxWebSocketProtocol.JsonOptions);
		await connection.GetSubscriber().PublishAsync(RedisChannel.Literal(redis.Channel), payload);
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		while (!stoppingToken.IsCancellationRequested)
		{
			var redis = _options.CurrentValue.Redis;
			if (redis?.Enabled != true)
			{
				try
				{
					await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				continue;
			}

			try
			{
				await ConnectAndSubscribeAsync(redis, stoppingToken);
				await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
			}
			catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
			{
				break;
			}
			catch (Exception exception)
			{
				_logger.LogError(exception, "Unable to connect the OPX WebSocket Redis backplane. Retrying.");
				await DisposeConnectionAsync();
				await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
			}
		}
	}

	public override async Task StopAsync(CancellationToken cancellationToken)
	{
		await base.StopAsync(cancellationToken);
		await DisposeConnectionAsync();
	}

	private async Task ConnectAndSubscribeAsync(OpxWebSocketRedisOptions options, CancellationToken cancellationToken)
	{
		var configuration = ConfigurationOptions.Parse(options.Configuration);
		configuration.AbortOnConnectFail = false;
		var connection = await ConnectionMultiplexer.ConnectAsync(configuration);
		var subscriber = connection.GetSubscriber();
		await subscriber.SubscribeAsync(RedisChannel.Literal(options.Channel), (channel, value) =>
		{
			_ = DispatchAsync(value.ToString(), cancellationToken);
		});
		_connection = connection;
		_logger.LogInformation("OPX WebSocket Redis backplane connected. Channel={Channel}", options.Channel);
	}

	private async Task DispatchAsync(string payload, CancellationToken cancellationToken)
	{
		try
		{
			var message = JsonSerializer.Deserialize<OpxWebSocketBackplaneMessage>(payload, OpxWebSocketProtocol.JsonOptions);
			if (message is not null && _receiver is not null)
			{
				await _receiver(message, cancellationToken);
			}
		}
		catch (Exception exception) when (exception is JsonException or OperationCanceledException)
		{
			_logger.LogWarning(exception, "Invalid OPX WebSocket backplane message ignored.");
		}
	}

	private async Task DisposeConnectionAsync()
	{
		var connection = Interlocked.Exchange(ref _connection, null);
		if (connection is not null)
		{
			await connection.DisposeAsync();
		}
	}
}
