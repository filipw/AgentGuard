using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.Secrets;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class SecretsDetectionRuleTests
{
    private static GuardrailContext CreateContext(string text) =>
        new() { Text = text, Phase = GuardrailPhase.Output };

    [Fact]
    public async Task ShouldPass_WhenNoSecrets()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("Hello, how are you today?"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenAwsAccessKeyDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("My key is AKIAIOSFODNN7EXAMPLE"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("aws-access-key");
    }

    [Fact]
    public async Task ShouldBlock_WhenGitHubTokenDetected()
    {
        var rule = new SecretsDetectionRule();
        var token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
        var result = await rule.EvaluateAsync(CreateContext($"Use this token: {token}"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("github-token");
    }

    [Fact]
    public async Task ShouldBlock_WhenGitHubSecretTokenDetected()
    {
        var rule = new SecretsDetectionRule();
        var token = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
        var result = await rule.EvaluateAsync(CreateContext($"Secret: {token}"));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_WhenJwtTokenDetected()
    {
        var rule = new SecretsDetectionRule();
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        var result = await rule.EvaluateAsync(CreateContext($"Your token: {jwt}"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("jwt-token");
    }

    [Fact]
    public async Task ShouldBlock_WhenPrivateKeyDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("-----BEGIN RSA PRIVATE KEY-----\nMIIEpA..."));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("private-key");
    }

    [Fact]
    public async Task ShouldBlock_WhenApiKeyAssignmentDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("api_key=sk_live_1234567890abcdefghij"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("api-key");
    }

    [Fact]
    public async Task ShouldBlock_WhenBearerTokenDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_WhenSlackTokenDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("token: xoxb-1234567890-abcdefghij"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("slack-token");
    }

    [Fact]
    public async Task ShouldBlock_WhenConnectionStringDetected()
    {
        var rule = new SecretsDetectionRule();
        var connStr = "Server=myserver.database.windows.net;Database=mydb;User Id=admin;Password=s3cretP@ss!";
        var result = await rule.EvaluateAsync(CreateContext(connStr));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("connection-string");
    }

    [Fact]
    public async Task ShouldBlock_WhenMongoDbUriDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("mongodb+srv://admin:password123@cluster0.abc.mongodb.net/mydb"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("mongodb-uri");
    }

    [Fact]
    public async Task ShouldBlock_WhenRedisUriDetected()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("redis://:mypassword@redis.example.com:6379"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("redis-uri");
    }

    [Fact]
    public async Task ShouldRedact_WhenRedactActionConfigured()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });
        var result = await rule.EvaluateAsync(CreateContext("Key: AKIAIOSFODNN7EXAMPLE is here"));
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("[SECRET_REDACTED]");
        result.ModifiedText.Should().NotContain("AKIAIOSFODNN7EXAMPLE");
    }

    [Fact]
    public async Task ShouldRedact_WithCustomReplacement()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Action = SecretAction.Redact,
            Replacement = "***"
        });
        var result = await rule.EvaluateAsync(CreateContext("Key: AKIAIOSFODNN7EXAMPLE here"));
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("***");
    }

    [Fact]
    public async Task ShouldDetect_WhenHighEntropyEnabled()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.GenericHighEntropy
        });
        // A random-looking high-entropy string
        var result = await rule.EvaluateAsync(CreateContext("token: aB3cD4eF5gH6iJ7kL8mN9oP0qR"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("high-entropy-string");
    }

    [Fact]
    public async Task ShouldPass_WhenHighEntropyDisabled_WithRandomString()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.GenericHighEntropy
        });
        // Regular English text has low entropy
        var result = await rule.EvaluateAsync(CreateContext("The quick brown fox jumps over the lazy dog"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldDetect_CustomPatterns()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.None,
            CustomPatterns = new Dictionary<string, string>
            {
                ["my-secret-format"] = @"MYSECRET_[A-Z0-9]{16}"
            }
        });
        var result = await rule.EvaluateAsync(CreateContext("Use MYSECRET_ABCDEF1234567890"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("my-secret-format");
    }

    [Fact]
    public async Task ShouldPass_WhenCategoriesDisabled()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.None
        });
        var result = await rule.EvaluateAsync(CreateContext("AKIAIOSFODNN7EXAMPLE"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenEmptyInput()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext(""));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = new SecretsDetectionRule();
        rule.Name.Should().Be("secrets-detection");
        rule.Phase.Should().Be(GuardrailPhase.Both);
        rule.Order.Should().Be(22);
    }

    [Fact]
    public async Task ShouldIncludeMetadata_WhenBlocking()
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext("AKIAIOSFODNN7EXAMPLE"));
        result.Metadata.Should().NotBeNull();
        result.Metadata!["detectedCategories"].Should().BeOfType<string[]>();
        result.Severity.Should().Be(GuardrailSeverity.Critical);
    }

    [Theory]
    [InlineData("-----BEGIN EC PRIVATE KEY-----")]
    [InlineData("-----BEGIN DSA PRIVATE KEY-----")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----")]
    [InlineData("-----BEGIN PRIVATE KEY-----")]
    public async Task ShouldBlock_VariousPrivateKeyFormats(string keyHeader)
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext(keyHeader));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void ShannonEntropy_ShouldBeHigh_ForRandomString()
    {
        var entropy = SecretsDetectionRule.CalculateShannonEntropy("aB3cD4eF5gH6iJ7kL8mN9oP0qR");
        entropy.Should().BeGreaterThan(4.0);
    }

    [Fact]
    public void ShannonEntropy_ShouldBeLow_ForRepetitiveString()
    {
        var entropy = SecretsDetectionRule.CalculateShannonEntropy("aaaaaaaaaaaaaaaaaaa");
        entropy.Should().Be(0);
    }

    // False positive tests - these should NOT trigger
    [Theory]
    [InlineData("The API documentation is available at /docs/api")]
    [InlineData("Please set the access_token_lifetime to 3600 seconds")]
    [InlineData("The bearer market is volatile")]
    [InlineData("Our server is running on port 8080")]
    [InlineData("The database connection timed out")]
    [InlineData("I need to begin private key negotiations")]
    public async Task ShouldPass_FalsePositives(string input)
    {
        var rule = new SecretsDetectionRule();
        var result = await rule.EvaluateAsync(CreateContext(input));
        result.IsBlocked.Should().BeFalse(because: $"'{input}' should not be flagged as a secret");
    }

    // AWS keys with the keyword before the value, and 88-character Azure storage keys

    [Theory]
    [InlineData("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")]
    [InlineData("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")]
    [InlineData("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY is my aws secret key")]
    public async Task ShouldDetect_AwsSecretKey_RegardlessOfKeywordPosition(string input)
    {
        var rule = new SecretsDetectionRule();

        var result = await rule.EvaluateAsync(CreateContext(input));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("aws-secret-key");
    }

    [Fact]
    public async Task ShouldNotDetect_A40CharTokenWithoutAwsContext()
    {
        var rule = new SecretsDetectionRule();

        var result = await rule.EvaluateAsync(CreateContext("the build id is wJalrXUtnFEMIxK7MDENGxbPxRfiCYEXAMPLEKEY"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldDetect_AzureStorageAccountKey()
    {
        var key = new string('A', 86) + "==";
        var rule = new SecretsDetectionRule();

        var result = await rule.EvaluateAsync(CreateContext($"DefaultEndpointsProtocol=https;AccountKey={key};"));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("azure-storage-key");
    }

    [Fact]
    public async Task ShouldInsertReplacementVerbatim_WhenItContainsDollarSequences()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Action = SecretAction.Redact,
            Replacement = "<$1-removed>"
        });

        var result = await rule.EvaluateAsync(CreateContext("token ghp_abcdefghijklmnopqrstuvwxyz0123456789 here"));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<$1-removed>");
    }

    // redaction covers the whole PEM block: header, key body and footer

    private const string KeyLine = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";

    internal static string KeyBody(int lines) => string.Join("\n", Enumerable.Repeat(KeyLine, lines));

    [Theory]
    [InlineData("RSA PRIVATE KEY")]
    [InlineData("EC PRIVATE KEY")]
    [InlineData("DSA PRIVATE KEY")]
    [InlineData("OPENSSH PRIVATE KEY")]
    [InlineData("ENCRYPTED PRIVATE KEY")]
    [InlineData("PRIVATE KEY")]
    [InlineData("PGP PRIVATE KEY BLOCK")]
    public async Task ShouldRedactTheWholeBlock_WhenAPrivateKeyIsFound(string label)
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });
        var text = $"Here is the key:\n-----BEGIN {label}-----\n{KeyBody(3)}\n-----END {label}-----\nDone.";

        var result = await rule.EvaluateAsync(CreateContext(text));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be("Here is the key:\n[SECRET_REDACTED]\nDone.");
    }

    [Fact]
    public async Task ShouldRedactEachPrivateKeyBlock_WhenThereAreSeveral()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });
        var text = $"A\n-----BEGIN RSA PRIVATE KEY-----\n{KeyBody(2)}\n-----END RSA PRIVATE KEY-----\n"
            + $"B\n-----BEGIN OPENSSH PRIVATE KEY-----\n{KeyBody(2)}\n-----END OPENSSH PRIVATE KEY-----\nC";

        var result = await rule.EvaluateAsync(CreateContext(text));

        result.ModifiedText.Should().Be("A\n[SECRET_REDACTED]\nB\n[SECRET_REDACTED]\nC");
    }

    [Theory]
    // no END line at all - e.g. a truncated reply
    [InlineData("")]
    // an END line that does not close this block
    [InlineData("\n-----END EC PRIVATE KEY-----\ntrailing text")]
    public async Task ShouldRedactToTheEnd_WhenThePrivateKeyBlockIsNotClosed(string tail)
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });

        var result = await rule.EvaluateAsync(CreateContext($"Key:\n-----BEGIN RSA PRIVATE KEY-----\n{KeyBody(3)}{tail}"));

        result.ModifiedText.Should().Be("Key:\n[SECRET_REDACTED]");
    }

    [Fact]
    public async Task ShouldBlock_WhenAPrivateKeyBlockIsFound()
    {
        var rule = new SecretsDetectionRule();

        var result = await rule.EvaluateAsync(CreateContext(
            $"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{KeyBody(3)}\n-----END ENCRYPTED PRIVATE KEY-----"));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("private-key");
    }

    [Fact]
    public void ShouldThrow_WhenMinHighEntropyLengthIsTooSmall()
    {
        var act = () => new SecretsDetectionRule(new SecretsDetectionOptions { MinHighEntropyLength = 0 });

        act.Should().Throw<ArgumentException>();
    }
}

// scans a large unterminated key block on purpose, so it runs in the non-parallel large-input
// collection
[Collection(LargeInputTestGroup.Name)]
public class SecretsDetectionRuleLargeInputTests
{
    // a large unterminated block, and many headers without END lines, come back fully redacted
    [Theory]
    [InlineData(1)]
    [InlineData(1_000)]
    public async Task ShouldRedactWithinTheMatchTimeout_WhenALargePrivateKeyBlockIsUnterminated(int headers)
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });
        var section = $"-----BEGIN RSA PRIVATE KEY-----\n{SecretsDetectionRuleTests.KeyBody(2)}\n";
        var text = "Key:\n" + string.Concat(Enumerable.Repeat(section, headers)) + SecretsDetectionRuleTests.KeyBody(2_000 / headers);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Output });

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be("Key:\n[SECRET_REDACTED]");
    }
}
