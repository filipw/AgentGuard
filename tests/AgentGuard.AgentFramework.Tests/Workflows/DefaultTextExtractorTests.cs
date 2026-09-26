using System.Globalization;
using AgentGuard.AgentFramework.Workflows;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.AgentFramework.Workflows.Tests;

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
    public void ShouldReturnEveryMessageText_WhenMessageIsAgentResponse()
    {
        var response = new AgentResponse
        {
            Messages =
            [
                new ChatMessage(ChatRole.Assistant, "first answer"),
                new ChatMessage(ChatRole.Tool, [new FunctionResultContent("call-1", "42")]),
                new ChatMessage(ChatRole.Assistant, "second answer")
            ]
        };

        _extractor.ExtractText(response).Should().Be("first answer\nsecond answer");
    }

    [Fact]
    public void ShouldReturnEmptyString_WhenAgentResponseHasNoText()
    {
        var response = new AgentResponse
        {
            Messages = [new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("call-1", "lookup")])]
        };

        _extractor.ExtractText(response).Should().BeEmpty();
    }

    [Fact]
    public void ShouldReturnEveryMessageText_WhenMessageIsEnumerableOfChatMessage()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "first"),
            new(ChatRole.Assistant, "second")
        };

        _extractor.ExtractText(messages).Should().Be("first\nsecond");
    }

    [Fact]
    public void ShouldReturnEveryMessageText_WhenMessageIsChatMessageArray()
    {
        ChatMessage[] messages = [new(ChatRole.System, "be brief"), new(ChatRole.User, "hello")];

        _extractor.ExtractText(messages).Should().Be("be brief\nhello");
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
        public override string ToString() => value.ToString(CultureInfo.InvariantCulture);
    }
}
