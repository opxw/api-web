// Copyright (c) 2026 - opx
using System.Diagnostics;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Opx.Api.Web.WebSockets;

namespace Opx.Api.Web.Tests;

[TestFixture]
public sealed class OpxWebSocketTests
{
	[Test]
	public async Task WebSocket_WhenEnabled_IsMappedAndEchoesText()
	{
		await using var app = await CreateAppAsync();
		using var socket = await ConnectAsync(app);

		await socket.SendAsync(Encoding.UTF8.GetBytes("hello"), WebSocketMessageType.Text, true, CancellationToken.None);
		var response = await ReceiveTextAsync(socket);

		Assert.That(response, Is.EqualTo("hello"));
	}

	[Test]
	public async Task WebSocket_ConnectionManager_CanBroadcastJson()
	{
		await using var app = await CreateAppAsync();
		using var socket = await ConnectAsync(app);
		var connections = app.Services.GetRequiredService<IOpxWebSocketConnectionManager>();

		await WaitUntilAsync(() => connections.Count == 1);
		await connections.BroadcastJsonAsync(new { type = "updated", id = 7 });
		var response = await ReceiveTextAsync(socket);

		Assert.Multiple(() =>
		{
			Assert.That(response, Does.Contain("\"type\":\"updated\""));
			Assert.That(response, Does.Contain("\"id\":7"));
		});
	}

	[Test]
	public async Task WebSocket_WhenMessageExceedsLimit_ClosesWithMessageTooBig()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:WebSocket:ReceiveBufferBytes"] = "1024",
			["OpxApiProtection:WebSocket:MaxMessageBytes"] = "1024"
		});
		using var socket = await ConnectAsync(app);

		await socket.SendAsync(new byte[1025], WebSocketMessageType.Binary, true, CancellationToken.None);
		var buffer = new byte[128];
		var result = await socket.ReceiveAsync(buffer.AsMemory(), CancellationToken.None);

		Assert.Multiple(() =>
		{
			Assert.That(result.MessageType, Is.EqualTo(WebSocketMessageType.Close));
			Assert.That(socket.CloseStatus, Is.EqualTo(WebSocketCloseStatus.MessageTooBig));
		});
	}

	[Test]
	public async Task WebSocket_WhenRateLimitExceeded_ClosesWithPolicyViolation()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:WebSocket:MessageRateLimit"] = "1",
			["OpxApiProtection:WebSocket:MessageRateLimitWindowSeconds"] = "60"
		});
		using var socket = await ConnectAsync(app);

		await socket.SendAsync(Encoding.UTF8.GetBytes("first"), WebSocketMessageType.Text, true, CancellationToken.None);
		Assert.That(await ReceiveTextAsync(socket), Is.EqualTo("first"));
		await socket.SendAsync(Encoding.UTF8.GetBytes("second"), WebSocketMessageType.Text, true, CancellationToken.None);
		var result = await socket.ReceiveAsync(new byte[128].AsMemory(), CancellationToken.None);

		Assert.Multiple(() =>
		{
			Assert.That(result.MessageType, Is.EqualTo(WebSocketMessageType.Close));
			Assert.That(socket.CloseStatus, Is.EqualTo(WebSocketCloseStatus.PolicyViolation));
		});
	}

	[Test]
	public async Task WebSocket_FiveHundredRoundTrips_CompletesWithinFiveSeconds()
	{
		await using var app = await CreateAppAsync(new Dictionary<string, string?>
		{
			["OpxApiProtection:WebSocket:MessageRateLimit"] = "1000"
		});
		using var socket = await ConnectAsync(app);
		var payload = Encoding.UTF8.GetBytes("ping");
		var stopwatch = Stopwatch.StartNew();

		for (var index = 0; index < 500; index++)
		{
			await socket.SendAsync(payload, WebSocketMessageType.Text, true, CancellationToken.None);
			Assert.That(await ReceiveTextAsync(socket), Is.EqualTo("ping"));
		}

		stopwatch.Stop();
		TestContext.Out.WriteLine($"WebSocket 500 sequential round trips: {stopwatch.ElapsedMilliseconds} ms");
		Assert.That(stopwatch.Elapsed, Is.LessThan(TimeSpan.FromSeconds(5)));
	}

	[Test]
	public async Task WebSocket_TopicSubscription_ReceivesOnlyTopicDelivery()
	{
		await using var app = await CreateAppAsync();
		using var socket = await ConnectAsync(app);
		await SendMessageAsync(socket, "opx.subscribe", new { topic = "sales" }, topic: "sales");
		Assert.That((await ReceiveMessageAsync(socket)).Type, Is.EqualTo("opx.subscribed"));

		var connections = app.Services.GetRequiredService<IOpxWebSocketConnectionManager>();
		await connections.SendToTopicAsync("sales", "sales.updated", new { total = 42 });
		var message = await ReceiveMessageAsync(socket);

		Assert.Multiple(() =>
		{
			Assert.That(message.Type, Is.EqualTo("sales.updated"));
			Assert.That(message.Topic, Is.EqualTo("sales"));
			Assert.That(message.GetData<JsonElement>().GetProperty("total").GetInt32(), Is.EqualTo(42));
		});
	}

	[Test]
	public async Task WebSocket_UserWithMultipleConnections_ReceivesOnEveryConnection()
	{
		await using var app = await CreateAppAsync();
		using var first = await ConnectAsync(app, "alice");
		using var second = await ConnectAsync(app, "alice");
		var connections = app.Services.GetRequiredService<IOpxWebSocketConnectionManager>();
		await WaitUntilAsync(() => connections.Count == 2);

		await connections.SendToUserAsync("alice", "user.updated", new { value = 7 });
		var firstMessage = await ReceiveMessageAsync(first);
		var secondMessage = await ReceiveMessageAsync(second);

		Assert.Multiple(() =>
		{
			Assert.That(firstMessage.Type, Is.EqualTo("user.updated"));
			Assert.That(secondMessage.Type, Is.EqualTo("user.updated"));
		});
	}

	[Test]
	public async Task WebSocket_TypedHandler_ReturnsResultAndAcknowledgement()
	{
		await using var app = await CreateAppAsync();
		using var socket = await ConnectAsync(app);

		await SendMessageAsync(socket, "test.echo", new { value = "hello" }, requireAck: true, messageId: "m1");
		var result = await ReceiveMessageAsync(socket);
		var acknowledgement = await ReceiveMessageAsync(socket);

		Assert.Multiple(() =>
		{
			Assert.That(result.Type, Is.EqualTo("test.echo.result"));
			Assert.That(acknowledgement.Type, Is.EqualTo("opx.ack"));
			Assert.That(acknowledgement.CorrelationId, Is.EqualTo("m1"));
		});
	}

	[Test]
	public async Task WebSocket_HealthMetrics_TrackConnectionsAndMessages()
	{
		await using var app = await CreateAppAsync();
		using var socket = await ConnectAsync(app);
		await socket.SendAsync(Encoding.UTF8.GetBytes("hello"), WebSocketMessageType.Text, true, CancellationToken.None);
		await ReceiveTextAsync(socket);
		var connections = app.Services.GetRequiredService<IOpxWebSocketConnectionManager>();
		var health = connections.GetHealth();
		var metrics = app.Services.GetRequiredService<Opx.Api.Web.Protection.OpxProtectionMetrics>();

		Assert.Multiple(() =>
		{
			Assert.That(health.ActiveConnections, Is.EqualTo(1));
			Assert.That(metrics.WebSocketMessagesReceived, Is.GreaterThanOrEqualTo(1));
			Assert.That(metrics.WebSocketMessagesSent, Is.GreaterThanOrEqualTo(1));
		});
	}

	private static async Task<WebApplication> CreateAppAsync(Dictionary<string, string?>? overrides = null)
	{
		var settings = new Dictionary<string, string?>
		{
			["OpxApiProtection:WebSocket:Enabled"] = "true",
			["OpxApiProtection:WebSocket:Path"] = "/ws",
			["OpxApiProtection:WebSocket:RequireAuthorization"] = "false",
			["OpxApiProtection:WebSocket:IdleTimeoutSeconds"] = "30",
			["OpxApiProtection:WebSocket:MessageRateLimit"] = "120",
			["OpxApiProtection:SecurityIssueLog:Enabled"] = "false"
		};
		foreach (var pair in overrides ?? [])
		{
			settings[pair.Key] = pair.Value;
		}

		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		builder.Configuration.AddInMemoryCollection(settings);
		builder.Services.UseOpxWebApi();
		builder.Services.AddOpxWebSocket<EchoWebSocketHandler>();
		builder.Services.AddOpxWebSocketMessageHandler<EchoTypedMessageHandler>();
		var app = builder.Build();
		app.Use(async (context, next) =>
		{
			var userId = context.Request.Headers["X-Test-User"].FirstOrDefault();
			if (!string.IsNullOrWhiteSpace(userId))
			{
				context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId)], "Test"));
			}
			await next();
		});
		app.UseOpxWebApiHandler();
		await app.StartAsync();
		return app;
	}

	private static Task<WebSocket> ConnectAsync(WebApplication app, string? userId = null)
	{
		var client = app.GetTestServer().CreateWebSocketClient();
		if (!string.IsNullOrWhiteSpace(userId))
		{
			client.ConfigureRequest = request => request.Headers["X-Test-User"] = userId;
		}
		return client.ConnectAsync(new Uri("ws://localhost/ws"), CancellationToken.None);
	}

	private static Task SendMessageAsync<T>(WebSocket socket, string type, T data, string? topic = null, bool requireAck = false, string? messageId = null)
	{
		var bytes = JsonSerializer.SerializeToUtf8Bytes(new
		{
			type,
			messageId = messageId ?? Guid.NewGuid().ToString("N"),
			topic,
			requireAck,
			data
		});
		return socket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None);
	}

	private static async Task<OpxWebSocketMessage> ReceiveMessageAsync(WebSocket socket)
	{
		var text = await ReceiveTextAsync(socket);
		return JsonSerializer.Deserialize<OpxWebSocketMessage>(text, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
	}

	private static async Task<string> ReceiveTextAsync(WebSocket socket)
	{
		var buffer = new byte[4096];
		var result = await socket.ReceiveAsync(buffer.AsMemory(), CancellationToken.None);
		Assert.That(result.MessageType, Is.EqualTo(WebSocketMessageType.Text));
		return Encoding.UTF8.GetString(buffer, 0, result.Count);
	}

	private static async Task WaitUntilAsync(Func<bool> condition)
	{
		var timeout = Stopwatch.StartNew();
		while (!condition() && timeout.Elapsed < TimeSpan.FromSeconds(2))
		{
			await Task.Delay(10);
		}

		Assert.That(condition(), Is.True);
	}

	public sealed class EchoWebSocketHandler : OpxWebSocketHandler
	{
		public override ValueTask OnTextMessageAsync(OpxWebSocketSession session, ReadOnlyMemory<byte> utf8Message, CancellationToken cancellationToken)
		{
			return new ValueTask(session.SendTextAsync(Encoding.UTF8.GetString(utf8Message.Span), cancellationToken));
		}
	}

	public sealed class EchoTypedMessageHandler : OpxWebSocketMessageHandler<JsonElement>
	{
		public override string Type => "test.echo";

		protected override ValueTask HandleAsync(OpxWebSocketSession session, JsonElement data, OpxWebSocketMessage message, CancellationToken cancellationToken)
		{
			return new ValueTask(session.SendMessageAsync("test.echo.result", data, correlationId: message.MessageId, cancellationToken: cancellationToken));
		}
	}
}
