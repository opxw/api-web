// Copyright (c) 2026 - opx
using System.Threading.Channels;

namespace Opx.Api.Web.Logs;

public sealed class OpxEndpointLogWriter : BackgroundService
{
	private readonly int _batchSize;
	private readonly Channel<EndpointLogEntry> _channel;
	private readonly TimeSpan _flushInterval;
	private readonly ILogger<OpxEndpointLogWriter> _logger;
	private long _droppedCount;

	public OpxEndpointLogWriter(ILogger<OpxEndpointLogWriter> logger, IConfiguration? configuration = null)
	{
		_logger = logger;
		var queueCapacity = Math.Max(1, configuration?.GetValue("EndpointLog:QueueCapacity", 8192) ?? 8192);
		_batchSize = Math.Max(1, configuration?.GetValue("EndpointLog:BatchSize", 100) ?? 100);
		var flushIntervalMs = Math.Max(1, configuration?.GetValue("EndpointLog:FlushIntervalMilliseconds", 250) ?? 250);
		_flushInterval = TimeSpan.FromMilliseconds(flushIntervalMs);
		_channel = Channel.CreateBounded<EndpointLogEntry>(new BoundedChannelOptions(queueCapacity)
		{
			FullMode = BoundedChannelFullMode.Wait,
			SingleReader = true,
			SingleWriter = false
		});
	}

	public long DroppedCount => Interlocked.Read(ref _droppedCount);

	public bool TryWrite(EndpointLogEntry entry)
	{
		if (_channel.Writer.TryWrite(entry))
		{
			return true;
		}

		Interlocked.Increment(ref _droppedCount);
		return false;
	}

	public async Task FlushAsync(CancellationToken cancellationToken = default)
	{
		var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
		await _channel.Writer.WriteAsync(EndpointLogEntry.CreateFlush(completion), cancellationToken);
		await completion.Task.WaitAsync(cancellationToken);
	}

	public override async Task StopAsync(CancellationToken cancellationToken)
	{
		try
		{
			await FlushAsync(cancellationToken);
		}
		catch (InvalidOperationException)
		{
		}

		_channel.Writer.TryComplete();
		await base.StopAsync(cancellationToken);

		var droppedCount = DroppedCount;
		if (droppedCount > 0)
		{
			_logger.LogWarning("Endpoint log writer dropped {DroppedCount} entries because the queue was full.", droppedCount);
		}
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		var batch = new List<EndpointLogEntry>(_batchSize);

		while (await _channel.Reader.WaitToReadAsync(CancellationToken.None))
		{
			batch.Clear();
			var deadline = TimeProvider.System.GetTimestamp() + (long)(_flushInterval.TotalSeconds * TimeProvider.System.TimestampFrequency);

			while (batch.Count < _batchSize && _channel.Reader.TryRead(out var entry))
			{
				batch.Add(entry);
			}

			while (batch.Count < _batchSize
				&& TimeProvider.System.GetTimestamp() < deadline
				&& _channel.Reader.TryRead(out var entry))
			{
				batch.Add(entry);
			}

			await WriteBatchAsync(batch, CancellationToken.None);
		}
	}

	private static async Task WriteBatchAsync(List<EndpointLogEntry> batch, CancellationToken cancellationToken)
	{
		var flushCompletions = new List<TaskCompletionSource>();
		foreach (var completion in batch.Where(entry => entry.FlushCompletion is not null).Select(entry => entry.FlushCompletion!))
		{
			flushCompletions.Add(completion);
		}

		foreach (var group in batch.Where(entry => entry.FilePath is not null).GroupBy(entry => entry.FilePath!))
		{
			var directory = Path.GetDirectoryName(group.Key);
			if (!string.IsNullOrWhiteSpace(directory))
			{
				Directory.CreateDirectory(directory);
			}

			var lines = group.Select(entry => $"{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff} {entry.Message}");
			await File.AppendAllLinesAsync(group.Key, lines, cancellationToken);
		}

		foreach (var completion in flushCompletions)
		{
			completion.TrySetResult();
		}
	}
}

public sealed record EndpointLogEntry(
	DateTime Timestamp,
	string Message,
	string? FilePath,
	TaskCompletionSource? FlushCompletion)
{
	public static EndpointLogEntry Create(string message, string filePath)
	{
		return new EndpointLogEntry(DateTime.Now, message, filePath, null);
	}

	public static EndpointLogEntry CreateFlush(TaskCompletionSource completion)
	{
		return new EndpointLogEntry(DateTime.Now, string.Empty, null, completion);
	}
}
