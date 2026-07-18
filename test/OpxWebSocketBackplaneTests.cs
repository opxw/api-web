// Copyright (c) 2026 - opx
using System.Net.WebSockets;
using System.Text;
using System.Threading.Channels;
using Microsoft.AspNetCore.Http;
using NUnit.Framework;
using Opx.Api.Web.Protection;
using Opx.Api.Web.WebSockets;

namespace Opx.Api.Web.Tests;

[TestFixture]
public sealed class OpxWebSocketBackplaneTests
{
	[Test]
	public async Task Backplane_TopicMessage_CrossesServerInstances()
	{
		var bus = new TestBackplaneBus();
		var first = new OpxWebSocketConnectionManager(bus.CreateEndpoint(), new OpxProtectionMetrics());
		var second = new OpxWebSocketConnectionManager(bus.CreateEndpoint(), new OpxProtectionMetrics());
		var recordingSocket = new RecordingWebSocket();
		await using var session = new OpxWebSocketSession("server-b-session", recordingSocket, new DefaultHttpContext());
		second.TryAdd(session);
		await second.AddToTopicAsync(session.Id, "sales");

		await first.SendToTopicAsync("sales", "sales.updated", new { total = 99 });
		var payload = await recordingSocket.Messages.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));

		Assert.Multiple(() =>
		{
			Assert.That(payload, Does.Contain("\"type\":\"sales.updated\""));
			Assert.That(payload, Does.Contain("\"total\":99"));
		});
	}

	private sealed class TestBackplaneBus
	{
		private readonly List<TestBackplane> _endpoints = [];

		public TestBackplane CreateEndpoint()
		{
			var endpoint = new TestBackplane(this);
			_endpoints.Add(endpoint);
			return endpoint;
		}

		public async ValueTask PublishAsync(OpxWebSocketBackplaneMessage message, CancellationToken cancellationToken)
		{
			foreach (var endpoint in _endpoints)
			{
				await endpoint.ReceiveAsync(message, cancellationToken);
			}
		}
	}

	private sealed class TestBackplane(TestBackplaneBus bus) : IOpxWebSocketBackplane
	{
		private Func<OpxWebSocketBackplaneMessage, CancellationToken, ValueTask>? _receiver;
		public bool Enabled => true;
		public bool IsConnected => true;
		public void SetReceiver(Func<OpxWebSocketBackplaneMessage, CancellationToken, ValueTask> receiver) => _receiver = receiver;
		public ValueTask PublishAsync(OpxWebSocketBackplaneMessage message, CancellationToken cancellationToken = default) => bus.PublishAsync(message, cancellationToken);
		public ValueTask ReceiveAsync(OpxWebSocketBackplaneMessage message, CancellationToken cancellationToken) => _receiver?.Invoke(message, cancellationToken) ?? ValueTask.CompletedTask;
	}

	private sealed class RecordingWebSocket : WebSocket
	{
		private WebSocketCloseStatus? _closeStatus;
		private string? _closeStatusDescription;
		private WebSocketState _state = WebSocketState.Open;
		public Channel<string> Messages { get; } = Channel.CreateUnbounded<string>();
		public override WebSocketCloseStatus? CloseStatus => _closeStatus;
		public override string? CloseStatusDescription => _closeStatusDescription;
		public override WebSocketState State => _state;
		public override string? SubProtocol => null;

		public override void Abort() => _state = WebSocketState.Aborted;
		public override Task CloseAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken cancellationToken)
		{
			_closeStatus = closeStatus;
			_closeStatusDescription = statusDescription;
			_state = WebSocketState.Closed;
			return Task.CompletedTask;
		}
		public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken cancellationToken)
			=> CloseAsync(closeStatus, statusDescription, cancellationToken);
		public override void Dispose() => _state = WebSocketState.Closed;
		public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken)
			=> throw new NotSupportedException();
		public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType, bool endOfMessage, CancellationToken cancellationToken)
		{
			Messages.Writer.TryWrite(Encoding.UTF8.GetString(buffer.Array!, buffer.Offset, buffer.Count));
			return Task.CompletedTask;
		}
	}
}
