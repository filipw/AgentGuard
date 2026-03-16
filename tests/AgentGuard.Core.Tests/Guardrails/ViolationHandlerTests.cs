using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Guardrails;

public class ViolationHandlerTests
{
    private static readonly GuardrailResult BlockedResult = GuardrailResult.Blocked("test violation");
    private static readonly GuardrailContext TestContext = new() { Text = "test", Phase = GuardrailPhase.Input };

    [Fact]
    public async Task DefaultHandler_ShouldReturnBlockReason()
    {
        var handler = new DefaultViolationHandler();
        var msg = await handler.HandleViolationAsync(BlockedResult, TestContext);
        msg.Should().Be("test violation");
    }

    [Fact]
    public async Task DefaultHandler_ShouldReturnDefaultMessage_WhenNoReason()
    {
        var handler = new DefaultViolationHandler();
        var result = new GuardrailResult { IsBlocked = true };
        var msg = await handler.HandleViolationAsync(result, TestContext);
        msg.Should().Be("I'm unable to process that request.");
    }

    [Fact]
    public async Task DefaultHandler_ShouldReturnCustomDefaultMessage()
    {
        var handler = new DefaultViolationHandler("Custom rejection.");
        var result = new GuardrailResult { IsBlocked = true };
        var msg = await handler.HandleViolationAsync(result, TestContext);
        msg.Should().Be("Custom rejection.");
    }

    [Fact]
    public async Task MessageHandler_ShouldReturnFixedMessage()
    {
        var handler = new MessageViolationHandler("Sorry, that's not allowed.");
        var msg = await handler.HandleViolationAsync(BlockedResult, TestContext);
        msg.Should().Be("Sorry, that's not allowed.");
    }

    [Fact]
    public async Task MessageHandler_ShouldIgnoreResultReason()
    {
        var handler = new MessageViolationHandler("Fixed message");
        var msg = await handler.HandleViolationAsync(BlockedResult, TestContext);
        msg.Should().Be("Fixed message");
    }

    [Fact]
    public async Task DelegateHandler_ShouldInvokeDelegate()
    {
        var handler = new DelegateViolationHandler((result, context, ct) =>
            ValueTask.FromResult($"Blocked by {result.RuleName}: {result.Reason} (agent: {context.AgentName})"));

        var result = GuardrailResult.Blocked("injection detected") with { RuleName = "prompt-injection" };
        var context = new GuardrailContext { Text = "test", Phase = GuardrailPhase.Input, AgentName = "TestAgent" };

        var msg = await handler.HandleViolationAsync(result, context);
        msg.Should().Be("Blocked by prompt-injection: injection detected (agent: TestAgent)");
    }

    [Fact]
    public async Task DelegateHandler_ShouldReceiveCancellationToken()
    {
        CancellationToken receivedToken = default;
        var handler = new DelegateViolationHandler((result, context, ct) =>
        {
            receivedToken = ct;
            return ValueTask.FromResult("ok");
        });

        using var cts = new CancellationTokenSource();
        await handler.HandleViolationAsync(BlockedResult, TestContext, cts.Token);
        receivedToken.Should().Be(cts.Token);
    }
}
