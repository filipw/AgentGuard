using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.Normalization;
using AgentGuard.Core.Rules.PII;
using AgentGuard.Core.Rules.PromptInjection;
using AgentGuard.Core.Rules.TokenLimits;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

/// <summary>
/// Regression tests that run a large corpus of safe, legitimate inputs through all
/// non-LLM guardrail rules at maximum sensitivity to catch false positives.
/// Any test failure here means a rule is incorrectly flagging benign content.
/// </summary>
public class FalsePositiveRegressionTests
{
    // Full pipeline with all local rules at max sensitivity
    private static readonly GuardrailPipeline Pipeline = CreatePipeline();

    private static GuardrailPipeline CreatePipeline()
    {
        var policy = new GuardrailPolicyBuilder("false-positive-test")
            .NormalizeInput()
            .BlockPromptInjection(Sensitivity.High)
            .RedactPII()
            .LimitInputTokens(10000)
            .Build();

        return new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);
    }

    private static GuardrailContext Ctx(string text) =>
        new() { Text = text, Phase = GuardrailPhase.Input };

    private async Task AssertSafe(string input)
    {
        var result = await Pipeline.RunAsync(Ctx(input));
        result.IsBlocked.Should().BeFalse(
            because: $"legitimate input should not be blocked: \"{Truncate(input)}\"");
    }

    private static string Truncate(string s) => s.Length > 80 ? s[..80] + "..." : s;

    // ── Everyday questions ──────────────────────────────────────

    [Theory]
    [InlineData("What's the weather like in Seattle today?")]
    [InlineData("Can you help me write a Python function to sort a list?")]
    [InlineData("Tell me about the history of the Roman Empire")]
    [InlineData("How do I reset my password?")]
    [InlineData("What are the instructions for assembling this IKEA shelf?")]
    [InlineData("What's the best recipe for chocolate chip cookies?")]
    [InlineData("Can you summarize this article for me?")]
    [InlineData("How do I configure my home router?")]
    [InlineData("What are the rules of chess?")]
    [InlineData("Tell me about the solar system")]
    [InlineData("I need help with my calculus homework")]
    [InlineData("What's new in .NET 10?")]
    [InlineData("Can you explain quantum computing in simple terms?")]
    [InlineData("What time zone is Tokyo in?")]
    [InlineData("How many calories are in a banana?")]
    public async Task ShouldPass_EverydayQuestions(string input) => await AssertSafe(input);

    // ── Technical / programming questions ────────────────────────

    [Theory]
    [InlineData("How do I create a new React component?")]
    [InlineData("What's the difference between TCP and UDP?")]
    [InlineData("Can you show me a SQL query to join two tables?")]
    [InlineData("How do I set up a CI/CD pipeline with GitHub Actions?")]
    [InlineData("What are the SOLID principles in software engineering?")]
    [InlineData("How do I use async/await in C#?")]
    [InlineData("Explain the difference between a stack and a queue")]
    [InlineData("How do I deploy a Docker container to Azure?")]
    [InlineData("What's the best way to handle errors in Go?")]
    [InlineData("Can you explain how garbage collection works in .NET?")]
    [InlineData("How do I write unit tests with xUnit?")]
    [InlineData("What are the new features in Python 3.12?")]
    [InlineData("How do I configure a reverse proxy with nginx?")]
    [InlineData("Can you show me how to parse JSON in JavaScript?")]
    [InlineData("What is dependency injection and why should I use it?")]
    public async Task ShouldPass_TechnicalQuestions(string input) => await AssertSafe(input);

    // ── Sentences containing "tricky" words that overlap with injection patterns ──

    [Theory]
    [InlineData("Please explain how the system works")]
    [InlineData("Can you tell me about the new rules in basketball?")]
    [InlineData("What are the instructions for this board game?")]
    [InlineData("I need to override the default settings in VS Code")]
    [InlineData("How do I ignore files in .gitignore?")]
    [InlineData("Tell me about the previous version of this software")]
    [InlineData("I want to forget about this topic and move on")]
    [InlineData("Can you pretend this is a different scenario for testing?")]
    [InlineData("Act as a guide and show me the best restaurants")]
    [InlineData("The system prompt told me to check the documentation")]
    [InlineData("What are the new instructions for the updated policy?")]
    [InlineData("How do I disregard notifications on my phone?")]
    [InlineData("I'd like to override the CSS styles on this page")]
    [InlineData("Can you show me the prompt engineering best practices?")]
    [InlineData("How do I configure system prompts for my chatbot?")]
    public async Task ShouldPass_SentencesWithOverlappingWords(string input) => await AssertSafe(input);

    // ── Numbers and data ────────────────────────────────────────

    [Theory]
    [InlineData("I have 3 cats and 4 dogs")]
    [InlineData("The meeting is at 3:00 PM on the 4th floor")]
    [InlineData("My order number is 1234567890")]
    [InlineData("The score was 7 to 3 in the final quarter")]
    [InlineData("Add 15 items to my cart")]
    [InlineData("The temperature is 72 degrees Fahrenheit")]
    [InlineData("I need 5 copies of this document")]
    [InlineData("The building has 30 floors and 4 elevators")]
    [InlineData("Chapter 3: Advanced Topics")]
    [InlineData("Version 4.0.1 was released on March 15th")]
    [InlineData("There are approximately 7.9 billion people on Earth")]
    [InlineData("My flight is BA 747, departing at 14:30")]
    public async Task ShouldPass_NumbersAndData(string input) => await AssertSafe(input);

    // ── Business / professional language ────────────────────────

    [Theory]
    [InlineData("Please forward this email to the team")]
    [InlineData("Can you summarize the key points from the meeting?")]
    [InlineData("I need to update the project timeline")]
    [InlineData("What are the compliance rules for this industry?")]
    [InlineData("How do I file a bug report?")]
    [InlineData("Can you draft an email to the client about the delay?")]
    [InlineData("What's the company policy on remote work?")]
    [InlineData("I need to schedule a follow-up meeting")]
    [InlineData("How do I submit a request for new equipment?")]
    [InlineData("What are the steps for the new onboarding process?")]
    [InlineData("The previous quarter's results exceeded expectations")]
    [InlineData("We need to comply with the new regulations")]
    [InlineData("How do I configure the new system settings?")]
    [InlineData("The report shows a 15% increase from last year")]
    public async Task ShouldPass_BusinessLanguage(string input) => await AssertSafe(input);

    // ── Creative writing and storytelling ────────────────────────

    [Theory]
    [InlineData("Write me a short story about a detective solving a mystery")]
    [InlineData("Can you write a poem about autumn?")]
    [InlineData("Help me brainstorm ideas for a fantasy novel")]
    [InlineData("Write a dialogue between two friends planning a trip")]
    [InlineData("Can you help me write a cover letter for a software engineering position?")]
    [InlineData("Write a product description for a wireless headphone")]
    [InlineData("Help me come up with a tagline for my bakery")]
    [InlineData("Can you write a birthday message for my colleague?")]
    [InlineData("Write a fictional story where two robots become friends")]
    [InlineData("Help me write song lyrics about the ocean")]
    public async Task ShouldPass_CreativeWriting(string input) => await AssertSafe(input);

    // ── Education and learning ──────────────────────────────────

    [Theory]
    [InlineData("Explain photosynthesis to a 10-year-old")]
    [InlineData("What are the main causes of World War I?")]
    [InlineData("How does the immune system fight infections?")]
    [InlineData("What is the theory of relativity?")]
    [InlineData("Can you explain how neural networks learn?")]
    [InlineData("What are the branches of government?")]
    [InlineData("How do volcanoes form?")]
    [InlineData("Explain the water cycle")]
    [InlineData("What is supply and demand in economics?")]
    [InlineData("How do vaccines work?")]
    public async Task ShouldPass_EducationQuestions(string input) => await AssertSafe(input);

    // ── Sentences that sound vaguely like attacks but aren't ────

    [Theory]
    [InlineData("My system is not working properly, can you help?")]
    [InlineData("I want to act as a mentor for new employees")]
    [InlineData("Can you pretend that I'm a customer calling for support?")]
    [InlineData("The new rules for the game are quite complex")]
    [InlineData("I need to override the auto-save feature in Word")]
    [InlineData("How do I ignore merge conflicts in git?")]
    [InlineData("Tell me about previous versions of the iPhone")]
    [InlineData("I forgot my previous password, how do I reset it?")]
    [InlineData("The system administrator told me to restart the service")]
    [InlineData("How do I configure the prompt timeout in my terminal?")]
    [InlineData("Can you show me how to use the system function in C?")]
    [InlineData("I need to add a new rule to my firewall")]
    [InlineData("The previous instructions were unclear, can you clarify?")]
    [InlineData("What happens when you override a method in Java?")]
    [InlineData("How do I forget a Bluetooth device on my phone?")]
    [InlineData("I want to bypass the highway traffic")]
    [InlineData("Can you list the things that are not allowed in carry-on luggage?")]
    [InlineData("What are the restrictions for importing goods?")]
    [InlineData("How do I create a new role in AWS IAM?")]
    [InlineData("The injection mold needs to be replaced")]
    public async Task ShouldPass_VaguelyAttackLikeSentences(string input) => await AssertSafe(input);

    // ── Multi-language / international content ──────────────────

    [Theory]
    [InlineData("Bonjour, comment allez-vous aujourd'hui?")]
    [InlineData("Wie kann ich mein Passwort zurücksetzen?")]
    [InlineData("La temperatura es de 25 grados centígrados")]
    [InlineData("今日の天気はどうですか？")]
    [InlineData("Сколько стоит этот товар?")] // Russian: "How much does this product cost?"
    [InlineData("Πόσο κοστίζει αυτό;")] // Greek: "How much does this cost?"
    public async Task ShouldPass_InternationalContent(string input) => await AssertSafe(input);

    // ── Code snippets (should not be flagged) ───────────────────

    [Theory]
    [InlineData("How do I write `if (x > 5) { return true; }` in Python?")]
    [InlineData("What does `git reset --hard HEAD~1` do?")]
    [InlineData("Explain this regex: `[A-Za-z0-9+/]{4,}={0,2}`")]
    [InlineData("How do I use `System.Text.Json` to deserialize JSON?")]
    [InlineData("What's the difference between `var` and `let` in JavaScript?")]
    [InlineData("Can you explain this SQL: SELECT * FROM users WHERE role = 'admin'?")]
    [InlineData("How do I use the `override` keyword in C#?")]
    [InlineData("What does `export default function App()` do in React?")]
    public async Task ShouldPass_CodeSnippets(string input) => await AssertSafe(input);

    // ── Long-form inputs ────────────────────────────────────────

    [Fact]
    public async Task ShouldPass_LongLegitimateInput()
    {
        var input = """
            I'm working on a project that involves building a web application using ASP.NET Core.
            The application needs to handle user authentication, process payments, and generate
            reports. I've been using Entity Framework Core for the database layer and I'm wondering
            about the best practices for structuring my repositories. Should I use the repository
            pattern or just use DbContext directly? Also, I need to implement rate limiting on my
            API endpoints. What's the recommended approach in .NET 8? I've heard about the built-in
            rate limiting middleware but I'm not sure how to configure it for different endpoints
            with different limits. Finally, I need to set up monitoring and logging. Should I use
            Application Insights or is there a better alternative for a self-hosted application?
            """;
        await AssertSafe(input);
    }

    [Fact]
    public async Task ShouldPass_LegitimateEmailDraft()
    {
        var input = """
            Can you help me draft an email? Here's the context: I need to inform my team about
            the new project timeline. The previous deadline was March 15th, but we need to extend
            it to April 1st due to unexpected technical challenges. I want to explain the reasons
            without sounding negative, and include action items for each team member. The tone
            should be professional but encouraging. Please also mention that the new system
            configuration guidelines are available on the wiki.
            """;
        await AssertSafe(input);
    }

    [Fact]
    public async Task ShouldPass_TechnicalDocumentation()
    {
        var input = """
            How do I document my API endpoints? I have the following routes:
            - GET /api/users - returns all users
            - POST /api/users - creates a new user
            - PUT /api/users/{id} - updates a user
            - DELETE /api/users/{id} - deletes a user
            Each endpoint requires an API key in the Authorization header. The system
            returns JSON responses with a status field. How do I generate OpenAPI/Swagger
            docs from this? Also, should I version my API using URL paths like /api/v1/users
            or use header-based versioning?
            """;
        await AssertSafe(input);
    }

    // ── Tricky edge cases that previously caused false positives ──

    [Theory]
    [InlineData("The base64 encoding of 'hello' is aGVsbG8=")] // short base64 mention
    [InlineData("Use \\x00 as a null terminator in C strings")] // hex in programming context
    [InlineData("The Unicode character U+200B is a zero-width space")] // talking ABOUT unicode
    [InlineData("In l33t speak, 'elite' is written as '3l1t3'")] // talking ABOUT leetspeak
    [InlineData("The === operator in JavaScript checks both type and value")]
    [InlineData("Use ### for h3 headings in Markdown")]
    [InlineData("The JSON format uses {\"key\": \"value\"} syntax")]
    [InlineData("I need to handle the [system] error in my log files")]
    [InlineData("The <system> tag is deprecated in this XML schema")]
    public async Task ShouldPass_TrickyEdgeCases(string input) => await AssertSafe(input);
}
