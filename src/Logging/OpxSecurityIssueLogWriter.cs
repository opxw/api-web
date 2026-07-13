// Copyright (c) 2026 - opx
using System.Threading.Channels;
using System.Text.Json;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.Logs;

public sealed class OpxSecurityIssueLogWriter : BackgroundService
{
	private const int DefaultBatchSize = 100;
	private static readonly TimeSpan DefaultFlushInterval = TimeSpan.FromMilliseconds(250);
	private readonly int _batchSize;
	private readonly Channel<SecurityIssueLogEntry> _channel;
	private readonly TimeSpan _flushInterval;
	private readonly ILogger<OpxSecurityIssueLogWriter> _logger;
	private readonly OpxProtectionMetrics? _metrics;
	private long _droppedCount;

	public OpxSecurityIssueLogWriter(
		ILogger<OpxSecurityIssueLogWriter> logger,
		IConfiguration? configuration = null,
		OpxProtectionMetrics? metrics = null)
	{
		_logger = logger;
		_metrics = metrics;
		var queueCapacity = Math.Max(1, configuration?.GetValue("OpxApiProtection:SecurityIssueLog:QueueCapacity", 8192) ?? 8192);
		_batchSize = Math.Max(1, configuration?.GetValue("OpxApiProtection:SecurityIssueLog:BatchSize", DefaultBatchSize) ?? DefaultBatchSize);
		var flushIntervalMs = Math.Max(1, configuration?.GetValue("OpxApiProtection:SecurityIssueLog:FlushIntervalMilliseconds", (int)DefaultFlushInterval.TotalMilliseconds) ?? (int)DefaultFlushInterval.TotalMilliseconds);
		_flushInterval = TimeSpan.FromMilliseconds(flushIntervalMs);
		_channel = Channel.CreateBounded<SecurityIssueLogEntry>(new BoundedChannelOptions(queueCapacity)
		{
			FullMode = BoundedChannelFullMode.Wait,
			SingleReader = true,
			SingleWriter = false
		});
	}

	public long DroppedCount => Interlocked.Read(ref _droppedCount);

	public bool TryWrite(SecurityIssueLogEntry entry)
	{
		if (_channel.Writer.TryWrite(entry))
		{
			_metrics?.IncrementSecurityIssueLogsQueued();
			return true;
		}

		Interlocked.Increment(ref _droppedCount);
		_metrics?.IncrementSecurityIssueLogsDropped();
		return false;
	}

	public async Task FlushAsync(CancellationToken cancellationToken = default)
	{
		var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
		await _channel.Writer.WriteAsync(SecurityIssueLogEntry.CreateFlush(completion), cancellationToken);
		await completion.Task.WaitAsync(cancellationToken);
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		var batch = new List<SecurityIssueLogEntry>(_batchSize);

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
			_logger.LogWarning("Security issue log writer dropped {DroppedCount} entries because the queue was full.", droppedCount);
		}
	}

	private async Task WriteBatchAsync(List<SecurityIssueLogEntry> batch, CancellationToken cancellationToken)
	{
		if (batch.Count == 0)
		{
			return;
		}

		var flushCompletions = new List<TaskCompletionSource>();
		foreach (var entry in batch)
		{
			if (entry.FlushCompletion is not null)
			{
				flushCompletions.Add(entry.FlushCompletion);
				continue;
			}

			if (entry.WriteLogger)
			{
				_logger.LogWarning("{Message}", entry.Message);
			}
		}

		foreach (var group in batch.Where(entry => entry.WriteFile && entry.FilePath is not null).GroupBy(entry => entry.FilePath!))
		{
			var directory = Path.GetDirectoryName(group.Key);
			if (!string.IsNullOrWhiteSpace(directory))
			{
				Directory.CreateDirectory(directory);
			}

			var lines = group.Select(entry => entry.Format.Equals("JsonLines", StringComparison.OrdinalIgnoreCase)
				? JsonSerializer.Serialize(new
				{
					timestamp = entry.Timestamp,
					type = "SecurityIssue",
					message = entry.Message
				})
				: $"{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff} {entry.Message}");
			await File.AppendAllLinesAsync(group.Key, lines, cancellationToken);
		}

		foreach (var completion in flushCompletions)
		{
			completion.TrySetResult();
		}
	}
}

public sealed record SecurityIssueLogEntry(
	DateTime Timestamp,
	string Message,
	bool WriteLogger,
	bool WriteFile,
	string? FilePath,
	string Format,
	TaskCompletionSource? FlushCompletion)
{
	public static SecurityIssueLogEntry Create(
		string message,
		bool writeLogger,
		bool writeFile,
		string? filePath,
		string format = "Text")
	{
		return new SecurityIssueLogEntry(DateTime.Now, message, writeLogger, writeFile, filePath, format, null);
	}

	public static SecurityIssueLogEntry CreateFlush(TaskCompletionSource completion)
	{
		return new SecurityIssueLogEntry(DateTime.Now, string.Empty, false, false, null, "Text", completion);
	}
}
