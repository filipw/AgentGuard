using AgentGuard.Workflows;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.Workflows.Tests;

public class DefaultTextExtractorTests
{
    private readonly DefaultTextExtractor _extractor = DefaultTextExtractor.Instance;

    [Fact]
    public void ShouldReturnNull_WhenMessageIsNull()
    {
        _extractor.ExtractText(null).Should().BeNull();
    }

    [Fact]
    public void ShouldReturnString_WhenMessageIsString()
    {
        _extractor.ExtractText("hello world").Should().Be("hello world");
    }

    [Fact]
    public void ShouldReturnText_WhenMessageIsChatMessage()
    {
        var msg = new ChatMessage(ChatRole.User, "test input");
        _extractor.ExtractText(msg).Should().Be("test input");
    }

    [Fact]
    public void ShouldReturnLastAssistantText_WhenMessageIsAgentResponse()
    {
        var response = new AgentResponse
        {
            Messages =
            [
                new ChatMessage(ChatRole.User, "question"),
                new ChatMessage(ChatRole.Assistant, "first answer"),
                new ChatMessage(ChatRole.Assistant, "second answer")
            ]
        };

        _extractor.ExtractText(response).Should().Be("second answer");
    }

    [Fact]
    public void ShouldReturnNull_WhenAgentResponseHasNoAssistantMessages()
    {
        var response = new AgentResponse
        {
            Messages = [new ChatMessage(ChatRole.User, "question")]
        };

        _extractor.ExtractText(response).Should().BeNull();
    }

    [Fact]
    public void ShouldReturnLastMessageText_WhenMessageIsEnumerableOfChatMessage()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "first"),
            new(ChatRole.Assistant, "second")
        };

        _extractor.ExtractText(messages).Should().Be("second");
    }

    [Fact]
    public void ShouldReturnTextProperty_WhenObjectHasPublicTextProperty()
    {
        var obj = new ObjectWithTextProperty { Text = "extracted" };
        _extractor.ExtractText(obj).Should().Be("extracted");
    }

    [Fact]
    public void ShouldFallbackToToString_WhenObjectHasNoTextProperty()
    {
        var obj = new ObjectWithoutTextProperty(42);
        _extractor.ExtractText(obj).Should().Be("42");
    }

    [Fact]
    public void ShouldReturnEmptyString_WhenMessageIsEmptyString()
    {
        _extractor.ExtractText("").Should().Be("");
    }

    private class ObjectWithTextProperty
    {
        public string? Text { get; set; }
    }

    private class ObjectWithoutTextProperty(int value)
    {
        public override string ToString() => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
