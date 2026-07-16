// Copyright (c) 2026 - opx
using System.Buffers;
using System.Diagnostics;
using System.Net.WebSockets;
using Microsoft.Extensions.Options;
using Opx.Api.Web.Logs;
using Opx.Api.Web.Protection;

namespace Opx.Api.Web.WebSockets;

internal sealed class OpxWebSocketEndpoint
{
	private readonly OpxWebSocketConnectionManager _connections;
	private readonly ILogger<OpxWebSocketEndpoint> _logger;
	private readonly IOptionsMonitor<OpxWebSocketOptions> _options;
	private readonly IServiceScopeFactory _scopeFactory;
	private readonly IConfiguration _configuration;
	private readonly IWebHostEnvironment _environment;
	private readonly OpxSecurityIssueLogWriter _securityIssueLogWriter;
	private readonly OpxProtectionMetrics _metrics;

	public OpxWebSocketEndpoint(
		OpxWebSocketConnectionManager connections,
		IOptionsMonitor<OpxWebSocketOptions> options,
		IServiceScopeFactory scopeFactory,
		IConfiguration configuration,
		IWebHostEnvironment environment,
		OpxSecurityIssueLogWriter securityIssueLogWriter,
		OpxProtectionMetrics metrics,
		ILogger<OpxWebSocketEndpoint> logger)
	{
		_connections = connections;
		_options = options;
		_scopeFactory = scopeFactory;
		_configuration = configuration;
		_environment = environment;
		_securityIssueLogWriter = securityIssueLogWriter;
		_metrics = metrics;
		_logger = logger;
	}

	public async Task HandleAsync(HttpContext context)
	{
		var options = Normalize(_options.CurrentValue);
		if (!context.WebSockets.IsWebSocketRequest)
		{
			context.Response.StatusCode = StatusCodes.Status400BadRequest;
			await context.Response.WriteAsJsonAsync(new { result = false, message = "WebSocket upgrade required" }, context.RequestAborted);
			return;
		}

		if (options.RequireAuthorization && context.User.Identity?.IsAuthenticated != true)
		{
			context.Response.StatusCode = StatusCodes.Status401Unauthorized;
			await context.Response.WriteAsJsonAsync(new { result = false, message = "Unauthorized" }, context.RequestAborted);
			return;
		}

		var subProtocol = ResolveSubProtocol(context, options.SubProtocol);
		if (options.SubProtocol is not null && subProtocol is null)
		{
			context.Response.StatusCode = StatusCodes.Status400BadRequest;
			await context.Response.WriteAsJsonAsync(new { result = false, message = "WebSocket subprotocol not supported" }, context.RequestAborted);
			return;
		}

		using var socket = await context.WebSockets.AcceptWebSocketAsync(subProtocol);
		await using var session = new OpxWebSocketSession(Guid.NewGuid().ToString("N"), socket, context, _metrics);
		await using var scope = _scopeFactory.CreateAsyncScope();
		var handler = scope.ServiceProvider.GetRequiredService<IOpxWebSocketHandler>();
		var router = scope.ServiceProvider.GetRequiredService<OpxWebSocketMessageRouter>();
		_connections.TryAdd(session);
		WebSocketCloseStatus? closeStatus = null;
		string? closeDescription = null;

		_logger.LogInformation("WebSocket connected. Session={SessionId} Path={Path} User={User}", session.Id, context.Request.Path, context.User.Identity?.Name ?? "-");
		try
		{
			await handler.OnConnectedAsync(session, context.RequestAborted);
			(closeStatus, closeDescription) = await ReceiveLoopAsync(session, handler, router, options, context.RequestAborted);
		}
		catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
		{
			closeStatus = WebSocketCloseStatus.EndpointUnavailable;
			closeDescription = "Request cancelled";
		}
		catch (WebSocketException exception)
		{
			closeStatus = socket.CloseStatus;
			closeDescription = socket.CloseStatusDescription ?? exception.WebSocketErrorCode.ToString();
			_logger.LogDebug(exception, "WebSocket disconnected unexpectedly. Session={SessionId}", session.Id);
		}
		finally
		{
			_connections.TryRemove(session.Id, out _);
			await handler.OnDisconnectedAsync(session, closeStatus, closeDescription, CancellationToken.None);
			_logger.LogInformation("WebSocket disconnected. Session={SessionId} Status={Status} Description={Description}", session.Id, closeStatus, closeDescription);
		}
	}

	private async Task<(WebSocketCloseStatus? Status, string? Description)> ReceiveLoopAsync(
		OpxWebSocketSession session,
		IOpxWebSocketHandler handler,
		OpxWebSocketMessageRouter router,
		OpxWebSocketOptions options,
		CancellationToken cancellationToken)
	{
		var receiveBuffer = ArrayPool<byte>.Shared.Rent(options.ReceiveBufferBytes);
		var messageBuffer = new ArrayBufferWriter<byte>(Math.Min(options.ReceiveBufferBytes, options.MaxMessageBytes));
		var windowStarted = Stopwatch.GetTimestamp();
		var messageCount = 0;

		try
		{
			while (session.State == WebSocketState.Open)
			{
				var result = await ReceiveAsync(session.Socket, receiveBuffer, options.IdleTimeoutSeconds, cancellationToken);
				if (result.MessageType == WebSocketMessageType.Close)
				{
					var closeStatus = session.Socket.CloseStatus ?? WebSocketCloseStatus.NormalClosure;
					var closeDescription = session.Socket.CloseStatusDescription;
					await session.CloseAsync(closeStatus, closeDescription, CancellationToken.None);
					return (closeStatus, closeDescription);
				}

				if (messageBuffer.WrittenCount + result.Count > options.MaxMessageBytes)
				{
					return await RejectAsync(session, WebSocketCloseStatus.MessageTooBig, "Message exceeds configured limit");
				}

				messageBuffer.Write(receiveBuffer.AsSpan(0, result.Count));
				if (!result.EndOfMessage)
				{
					continue;
				}

				if (!IsWithinRateLimit(ref windowStarted, ref messageCount, options))
				{
					return await RejectAsync(session, WebSocketCloseStatus.PolicyViolation, "Message rate limit exceeded");
				}

				if (result.MessageType == WebSocketMessageType.Text)
				{
					session.MarkReceived(messageBuffer.WrittenCount);
					if (!await router.TryRouteAsync(session, messageBuffer.WrittenMemory, cancellationToken))
					{
						await handler.OnTextMessageAsync(session, messageBuffer.WrittenMemory, cancellationToken);
					}
				}
				else
				{
					session.MarkReceived(messageBuffer.WrittenCount);
					await handler.OnBinaryMessageAsync(session, messageBuffer.WrittenMemory, cancellationToken);
				}

				messageBuffer.Clear();
			}
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(receiveBuffer);
		}

		return (session.Socket.CloseStatus, session.Socket.CloseStatusDescription);
	}

	private async Task<(WebSocketCloseStatus? Status, string? Description)> RejectAsync(
		OpxWebSocketSession session,
		WebSocketCloseStatus status,
		string reason)
	{
		session.HttpContext.Items["OpxWebSocketSecurityReason"] = reason;
		_metrics.IncrementWebSocketRejectedMessage();
		WriteSecurityIssue(session, reason);
		await session.CloseAsync(status, reason, CancellationToken.None);
		return (status, reason);
	}

	private void WriteSecurityIssue(OpxWebSocketSession session, string reason)
	{
		if (!_configuration.GetValue("OpxApiProtection:SecurityIssueLog:Enabled", true))
		{
			return;
		}

		var output = _configuration.GetValue("OpxApiProtection:SecurityIssueLog:Output", "File") ?? "File";
		var writeLogger = output.Equals("Logger", StringComparison.OrdinalIgnoreCase)
			|| output.Equals("Both", StringComparison.OrdinalIgnoreCase);
		var writeFile = output.Equals("File", StringComparison.OrdinalIgnoreCase)
			|| output.Equals("Both", StringComparison.OrdinalIgnoreCase);
		var filePath = _configuration.GetValue("OpxApiProtection:SecurityIssueLog:FilePath", "logs/security-issue-log-{date}.log")
			?? "logs/security-issue-log-{date}.log";
		filePath = filePath.Replace("{date}", DateTime.Now.ToString("yyyyMMdd"), StringComparison.OrdinalIgnoreCase);
		if (!Path.IsPathRooted(filePath))
		{
			filePath = Path.Combine(_environment.ContentRootPath, filePath);
		}

		var clientIp = OpxClientIpResolver.ResolveDetails(session.HttpContext, _configuration);
		var message = $"WebSocketSecurityIssue Path={session.HttpContext.Request.Path} Session={session.Id} IP={clientIp.Text} PeerIP={clientIp.PeerText} IPSource={clientIp.Source} Reason={reason}";
		var entry = SecurityIssueLogEntry.Create(
			message,
			writeLogger,
			writeFile,
			writeFile ? filePath : null,
			_configuration.GetValue("OpxApiProtection:SecurityIssueLog:Format", "Text") ?? "Text");
		if (!_securityIssueLogWriter.TryWrite(entry))
		{
			_logger.LogWarning("WebSocket security issue log queue is full. Session={SessionId} Reason={Reason}", session.Id, reason);
		}
	}

	private static async Task<ValueWebSocketReceiveResult> ReceiveAsync(
		WebSocket socket,
		Memory<byte> buffer,
		int idleTimeoutSeconds,
		CancellationToken cancellationToken)
	{
		if (idleTimeoutSeconds <= 0)
		{
			return await socket.ReceiveAsync(buffer, cancellationToken);
		}

		using var idleTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		idleTimeout.CancelAfter(TimeSpan.FromSeconds(idleTimeoutSeconds));
		try
		{
			return await socket.ReceiveAsync(buffer, idleTimeout.Token);
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			throw new WebSocketException(WebSocketError.ConnectionClosedPrematurely, "WebSocket idle timeout exceeded.");
		}
	}

	private static bool IsWithinRateLimit(ref long windowStarted, ref int messageCount, OpxWebSocketOptions options)
	{
		if (options.MessageRateLimit <= 0)
		{
			return true;
		}

		if (Stopwatch.GetElapsedTime(windowStarted).TotalSeconds >= options.MessageRateLimitWindowSeconds)
		{
			windowStarted = Stopwatch.GetTimestamp();
			messageCount = 0;
		}

		messageCount++;
		return messageCount <= options.MessageRateLimit;
	}

	private static string? ResolveSubProtocol(HttpContext context, string? configuredSubProtocol)
	{
		if (string.IsNullOrWhiteSpace(configuredSubProtocol))
		{
			return null;
		}

		return context.WebSockets.WebSocketRequestedProtocols.Contains(configuredSubProtocol, StringComparer.OrdinalIgnoreCase)
			? configuredSubProtocol
			: null;
	}

	private static OpxWebSocketOptions Normalize(OpxWebSocketOptions options)
	{
		var receiveBufferBytes = Math.Clamp(options.ReceiveBufferBytes, 1024, 1024 * 1024);
		return new OpxWebSocketOptions
		{
			Enabled = options.Enabled,
			Path = options.Path,
			RequireAuthorization = options.RequireAuthorization,
			SubProtocol = options.SubProtocol,
			KeepAliveIntervalSeconds = options.KeepAliveIntervalSeconds,
			KeepAliveTimeoutSeconds = options.KeepAliveTimeoutSeconds,
			ReceiveBufferBytes = receiveBufferBytes,
			MaxMessageBytes = Math.Max(receiveBufferBytes, options.MaxMessageBytes),
			IdleTimeoutSeconds = Math.Max(0, options.IdleTimeoutSeconds),
			MessageRateLimit = Math.Max(0, options.MessageRateLimit),
			MessageRateLimitWindowSeconds = Math.Max(1, options.MessageRateLimitWindowSeconds),
			EnableTypedRouting = options.EnableTypedRouting,
			EnableAcknowledgements = options.EnableAcknowledgements,
			MaxSubscriptionsPerConnection = Math.Max(1, options.MaxSubscriptionsPerConnection),
			MaxTopicLength = Math.Clamp(options.MaxTopicLength, 1, 512),
			Redis = options.Redis ?? new OpxWebSocketRedisOptions(),
			AllowedOrigins = options.AllowedOrigins ?? []
		};
	}
}
