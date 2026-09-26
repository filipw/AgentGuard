using System.Globalization;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.LLM;
using AgentGuard.Core.Telemetry;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

/// <summary>
/// Tests that switch the process-wide <see cref="AgentGuardTelemetry.EnableSensitiveData"/> flag.
/// </summary>
/// <remarks>
/// Parallelization is disabled, so xunit runs this collection on its own after the parallel ones
/// and no other test sees the flag change underneath it.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SensitiveDataTestGroup
{
    /// <summary>The collection name.</summary>
    public const string Name = "Sensitive data flag";
}

/// <summary>
/// A judge that ignores the requested format may quote the evaluated text, personal data
/// included. What it said reaches the error detail - and with it the logs and spans - only when
/// sensitive data capture is on.
/// </summary>
[Collection(SensitiveDataTestGroup.Name)]
public class LlmJudgePrivacyTests
{
    private const string OffFormatReply = "The customer Jane Doe (jane.doe@example.com, 555-0100) asks about her order.";

    private static IChatClient Judge(string response)
    {
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, response)));
        return mock.Object;
    }

    private static GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    private static async Task WithSensitiveData(bool enabled, Func<Task> test)
    {
        var previous = AgentGuardTelemetry.EnableSensitiveData;
        try
        {
            AgentGuardTelemetry.EnableSensitiveData = enabled;
            await test();
        }
        finally
        {
            AgentGuardTelemetry.EnableSensitiveData = previous;
        }
    }

    public static TheoryData<string> JudgeRules => ["injection", "topic", "pii-block", "pii-redact", "groundedness", "output-policy", "copyright"];

    private static IGuardrailRule CreateRule(string kind, IChatClient judge) => kind switch
    {
        "injection" => new LlmPromptInjectionRule(judge),
        "topic" => new LlmTopicGuardrailRule(judge, new LlmTopicGuardrailOptions { AllowedTopics = ["orders"] }),
        "pii-block" => new LlmPiiDetectionRule(judge, new LlmPiiDetectionOptions { Action = PiiAction.Block }),
        "pii-redact" => new LlmPiiDetectionRule(judge),
        "groundedness" => new LlmGroundednessRule(judge),
        "output-policy" => new LlmOutputPolicyRule(judge, new LlmOutputPolicyOptions { PolicyDescription = "be polite" }),
        "copyright" => new LlmCopyrightRule(judge),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    [Theory]
    [MemberData(nameof(JudgeRules))]
    public Task ShouldReportOnlyTheLength_WhenSensitiveDataIsOff(string kind) => WithSensitiveData(false, async () =>
    {
        var rule = CreateRule(kind, Judge(OffFormatReply));

        var result = await rule.EvaluateAsync(Ctx("Where is my order?"));

        result.IsError.Should().BeTrue();
        var detail = (string)result.Metadata!["errorDetail"];
        detail.Should().NotContain("Jane").And.NotContain("jane.doe@example.com").And.NotContain("555-0100");
        detail.Should().Contain(OffFormatReply.Length.ToString(CultureInfo.InvariantCulture));
    });

    [Fact]
    public Task ShouldIncludeTheJudgesText_WhenSensitiveDataIsOn() => WithSensitiveData(true, async () =>
    {
        var rule = new LlmPromptInjectionRule(Judge(OffFormatReply));

        var result = await rule.EvaluateAsync(Ctx("Where is my order?"));

        ((string)result.Metadata!["errorDetail"]).Should().Contain(OffFormatReply);
    });

    [Fact]
    public Task ShouldKeepTheJudgesTextOutOfThePipelineLog_WhenSensitiveDataIsOff() => WithSensitiveData(false, async () =>
    {
        var logger = new CapturingLogger();
        var policy = new GuardrailPolicy("privacy", [new LlmPromptInjectionRule(Judge(OffFormatReply))]);
        var pipeline = new GuardrailPipeline(policy, logger);

        await pipeline.RunAsync(Ctx("Where is my order?"));

        logger.Messages.Should().Contain(m => m.Contains("llm-prompt-injection", StringComparison.Ordinal));
        logger.Messages.Should().NotContain(m => m.Contains("Jane", StringComparison.Ordinal) || m.Contains("555-0100", StringComparison.Ordinal));
    });

    private sealed class CapturingLogger : ILogger<GuardrailPipeline>
    {
        private readonly List<string> _messages = [];
        private readonly Lock _lock = new();

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_lock)
                    return [.. _messages];
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_lock)
                _messages.Add(formatter(state, exception));
        }
    }
}
