using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Xunit;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// End-to-end tests for <see cref="LlmPiiDetectionRule"/> against a real LLM.
/// </summary>
public class LlmPiiDetectionE2ETests : IClassFixture<LlmTestFixture>
{
    private readonly LlmTestFixture _fixture;

    public LlmPiiDetectionE2ETests(LlmTestFixture fixture) => _fixture = fixture;

    [LlmFact]
    public async Task ShouldPass_CleanMessage()
    {
        var rule = new LlmPiiDetectionRule(_fixture.ChatClient!, chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "What is the weather like today in Seattle?", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("clean message should not be flagged");
        result.IsModified.Should().BeFalse();
    }

    [LlmFact]
    public async Task ShouldDetect_EmailAddress()
    {
        var rule = new LlmPiiDetectionRule(_fixture.ChatClient!,
            new LlmPiiDetectionOptions { Action = PiiAction.Block },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "Please send the report to john.doe@example.com", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("email address is PII");
    }

    [LlmFact]
    public async Task ShouldDetect_PhoneAndName()
    {
        var rule = new LlmPiiDetectionRule(_fixture.ChatClient!,
            new LlmPiiDetectionOptions { Action = PiiAction.Block },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "Contact Sarah Johnson at 555-123-4567 for details.", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("name and phone number are PII");
    }

    [LlmFact]
    public async Task ShouldRedact_WhenRedactMode()
    {
        var rule = new LlmPiiDetectionRule(_fixture.ChatClient!,
            new LlmPiiDetectionOptions { Action = PiiAction.Redact },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "My SSN is 123-45-6789 and my name is Alice Smith.", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);

        // The LLM should either redact (Modified) or block — either way it should not pass
        var detected = result.IsBlocked || result.IsModified;
        detected.Should().BeTrue("PII should be detected and redacted or blocked");

        if (result.IsModified)
        {
            result.ModifiedText.Should().NotBeNullOrEmpty();
            result.ModifiedText.Should().Contain("[REDACTED]", "redacted text should contain [REDACTED] markers");
            result.ModifiedText.Should().NotContain("123-45-6789", "SSN should be redacted");
        }
    }

    [LlmFact]
    public async Task ShouldPass_GenericBusinessMessage()
    {
        var rule = new LlmPiiDetectionRule(_fixture.ChatClient!,
            new LlmPiiDetectionOptions { Action = PiiAction.Block },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "The quarterly report shows a 15% increase in revenue.", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("generic business message has no PII");
    }
}
