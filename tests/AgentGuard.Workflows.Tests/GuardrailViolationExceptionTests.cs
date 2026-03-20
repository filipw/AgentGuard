using AgentGuard.Core.Abstractions;
using AgentGuard.Workflows;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Workflows.Tests;

public class GuardrailViolationExceptionTests
{
    [Fact]
    public void ShouldFormatMessage_WithExecutorIdPhaseAndReason()
    {
        var result = GuardrailResult.Blocked("PII detected");
        var ex = new GuardrailViolationException(result, GuardrailPhase.Input, "step-1");

        ex.Message.Should().Contain("step-1");
        ex.Message.Should().Contain("Input");
        ex.Message.Should().Contain("PII detected");
    }

    [Fact]
    public void ShouldPreserveAllProperties_WhenConstructed()
    {
        var result = GuardrailResult.Blocked("injection attempt", GuardrailSeverity.Critical);
        var ex = new GuardrailViolationException(result, GuardrailPhase.Output, "summarize-executor");

        ex.ViolationResult.Should().BeSameAs(result);
        ex.Phase.Should().Be(GuardrailPhase.Output);
        ex.ExecutorId.Should().Be("summarize-executor");
    }

    [Fact]
    public void ShouldBeAnException_WithCorrectInheritance()
    {
        var result = GuardrailResult.Blocked("violation");
        var ex = new GuardrailViolationException(result, GuardrailPhase.Input, "exec");

        ex.Should().BeAssignableTo<Exception>();
        ex.ViolationResult.IsBlocked.Should().BeTrue();
        ex.ViolationResult.Reason.Should().Be("violation");
    }
}
