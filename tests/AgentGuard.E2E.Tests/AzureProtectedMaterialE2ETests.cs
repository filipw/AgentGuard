using AgentGuard.Azure.ProtectedMaterial;
using AgentGuard.Core.Abstractions;
using FluentAssertions;
using Xunit;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// End-to-end tests for <see cref="AzureProtectedMaterialRule"/> with <see cref="AzureProtectedMaterialClient"/>
/// against a real Azure Content Safety endpoint.
/// </summary>
public class AzureProtectedMaterialE2ETests : IClassFixture<AzureProtectedMaterialTestFixture>
{
    private readonly AzureProtectedMaterialTestFixture _fixture;

    public AzureProtectedMaterialE2ETests(AzureProtectedMaterialTestFixture fixture) => _fixture = fixture;

    // --- Client: text - known copyrighted content should be detected ---

    [AzureProtectedMaterialFact]
    public async Task TextClient_ShouldDetect_KnownText()
    {
        // Hamlet's "To be, or not to be" soliloquy - a widely indexed literary passage that Azure
        // recognizes as known web content. Tests the API's ability to match text, not copyright status.
        var result = await _fixture.Client!.AnalyzeTextAsync(
            "To be, or not to be, that is the question: " +
            "Whether tis nobler in the mind to suffer " +
            "The slings and arrows of outrageous fortune, " +
            "Or to take arms against a sea of troubles " +
            "And by opposing end them. To die, to sleep " +
            "No more and by a sleep to say we end " +
            "The heart-ache and the thousand natural shocks " +
            "That flesh is heir to. Tis a consummation " +
            "Devoutly to be wished. To die, to sleep " +
            "To sleep, perchance to dream ay, there is the rub, " +
            "For in that sleep of death what dreams may come, " +
            "When we have shuffled off this mortal coil, " +
            "Must give us pause.");

        result.Detected.Should().BeTrue("well-known literary text should be detected as protected material");
        result.MaterialType.Should().Be(ProtectedMaterialType.Text);
    }

    // --- Client: text - original content should pass ---

    [AzureProtectedMaterialFact]
    public async Task TextClient_ShouldPass_OriginalContent()
    {
        var result = await _fixture.Client!.AnalyzeTextAsync(
            "The quarterly revenue report shows a 15% increase year-over-year. " +
            "Customer satisfaction metrics improved across all segments. " +
            "The engineering team successfully migrated to the new cloud infrastructure " +
            "resulting in 40% cost reduction in compute expenses.");

        result.Detected.Should().BeFalse("original business content is not copyrighted material");
        result.MaterialType.Should().Be(ProtectedMaterialType.Text);
    }

    [AzureProtectedMaterialFact]
    public async Task TextClient_ShouldPass_TechnicalExplanation()
    {
        var result = await _fixture.Client!.AnalyzeTextAsync(
            "A binary search tree is a data structure where each node has at most two children. " +
            "The left child contains values less than the parent, and the right child contains values " +
            "greater than the parent. This property enables O(log n) search operations on average.");

        result.Detected.Should().BeFalse("generic technical explanation is not protected material");
    }

    // --- Client: code - known GitHub code should be detected ---

    [AzureProtectedMaterialFact]
    public async Task CodeClient_ShouldDetect_KnownGitHubCode()
    {
        // Classic Quake III Arena fast inverse square root function - widely copied in GitHub repos, but still protected material
        var result = await _fixture.Client!.AnalyzeCodeAsync(
            "float Q_rsqrt(float number) { long i; float x2, y; const float threehalfs = 1.5F; x2 = number * 0.5F; y = number; i = *(long*)&y; i = 0x5f3759df - (i >> 1); y = *(float*)&i; y = y * (threehalfs - (x2 * y * y)); return y; }");

        result.Detected.Should().BeTrue("well-known GitHub code should be detected as protected material");
        result.MaterialType.Should().Be(ProtectedMaterialType.Code);
        result.CodeCitations.Should().NotBeEmpty("code detection should include citation information");
        result.CodeCitations[0].SourceUrls.Should().NotBeEmpty("citations should include source URLs");
    }

    // --- Client: code - original code should pass ---

    [AzureProtectedMaterialFact]
    public async Task CodeClient_ShouldPass_OriginalCode()
    {
        var result = await _fixture.Client!.AnalyzeCodeAsync(
            "public sealed class MyUniqueGuardrailProcessor { " +
            "private readonly string _customConfig; " +
            "public MyUniqueGuardrailProcessor(string config) => _customConfig = config; " +
            "public bool ProcessInput(string input) => !string.IsNullOrEmpty(input) && input.Length < 5000; }");

        result.Detected.Should().BeFalse("original simple code is not from known GitHub repos");
        result.MaterialType.Should().Be(ProtectedMaterialType.Code);
        result.CodeCitations.Should().BeEmpty();
    }

    // --- Rule: text detection in output phase ---

    [AzureProtectedMaterialFact]
    public async Task Rule_ShouldBlock_CopyrightedTextInOutput()
    {
        var rule = new AzureProtectedMaterialRule(_fixture.Client!);
        var ctx = new GuardrailContext
        {
            Text = "To be, or not to be, that is the question: " +
                   "Whether tis nobler in the mind to suffer " +
                   "The slings and arrows of outrageous fortune, " +
                   "Or to take arms against a sea of troubles " +
                   "And by opposing end them. To die, to sleep " +
                   "No more and by a sleep to say we end " +
                   "The heart-ache and the thousand natural shocks " +
                   "That flesh is heir to.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("well-known literary text should be blocked in output");
        result.Reason.Should().Contain("copyrighted text");
        result.Metadata.Should().ContainKey("materialType");
        result.Metadata!["materialType"].Should().Be("text");
    }

    [AzureProtectedMaterialFact]
    public async Task Rule_ShouldPass_OriginalOutput()
    {
        var rule = new AzureProtectedMaterialRule(_fixture.Client!);
        var ctx = new GuardrailContext
        {
            Text = "Here is a summary of the quarterly report: revenue increased 15%, " +
                   "customer satisfaction improved, and the team recommends European expansion in Q3.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("original summary should pass");
    }

    // --- Rule: code detection when enabled ---

    [AzureProtectedMaterialFact]
    public async Task Rule_ShouldBlock_ProtectedCode_WhenCodeAnalysisEnabled()
    {
        var rule = new AzureProtectedMaterialRule(_fixture.Client!, new AzureProtectedMaterialOptions
        {
            AnalyzeCode = true
        });

        var ctx = new GuardrailContext
        {
            // Use benign text so text check passes, but put protected code in Properties
            Text = "Here is the game code you requested.",
            Phase = GuardrailPhase.Output
        };
        ctx.Properties["Code"] =
            "float Q_rsqrt(float number) { long i; float x2, y; const float threehalfs = 1.5F; x2 = number * 0.5F; y = number; i = *(long*)&y; i = 0x5f3759df - (i >> 1); y = *(float*)&i; y = y * (threehalfs - (x2 * y * y)); return y; }";

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("protected GitHub code should be blocked when code analysis is enabled");
        result.Metadata.Should().ContainKey("materialType");
        result.Metadata!["materialType"].Should().Be("code");
        result.Metadata.Should().ContainKey("codeCitations");
    }

    [AzureProtectedMaterialFact]
    public async Task Rule_ShouldNotCheckCode_WhenCodeAnalysisDisabled()
    {
        var rule = new AzureProtectedMaterialRule(_fixture.Client!); // AnalyzeCode = false by default
        var ctx = new GuardrailContext
        {
            Text = "Here is the game code you requested.",
            Phase = GuardrailPhase.Output
        };
        ctx.Properties["Code"] =
            "python import pygame pygame.init() win = pygame.display.set_mode((500, 500))";

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("code should not be checked when AnalyzeCode is false");
    }

    // --- Rule: warn mode ---

    [AzureProtectedMaterialFact]
    public async Task Rule_ShouldWarn_WhenActionIsWarn()
    {
        var rule = new AzureProtectedMaterialRule(_fixture.Client!, new AzureProtectedMaterialOptions
        {
            Action = ProtectedMaterialAction.Warn
        });

        var ctx = new GuardrailContext
        {
            Text = "To be, or not to be, that is the question: " +
                   "Whether tis nobler in the mind to suffer " +
                   "The slings and arrows of outrageous fortune, " +
                   "Or to take arms against a sea of troubles " +
                   "And by opposing end them. To die, to sleep " +
                   "No more and by a sleep to say we end " +
                   "The heart-ache and the thousand natural shocks " +
                   "That flesh is heir to.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("warn mode should not block");
        result.Metadata.Should().ContainKey("materialType");
    }

    // --- Rule metadata ---

    [AzureProtectedMaterialFact]
    public async Task Rule_ShouldHaveCorrectMetadata()
    {
        var rule = new AzureProtectedMaterialRule(_fixture.Client!);
        rule.Name.Should().Be("azure-protected-material");
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Order.Should().Be(76);
    }
}
