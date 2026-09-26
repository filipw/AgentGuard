using System.Globalization;
using System.Text.RegularExpressions;
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

    // other private key armors: PGP with armor headers, PGP 2.x SECRET KEY BLOCK, SSH2, and
    // traditional encrypted PEM - the whole block goes, not just the header line

    [Theory]
    [InlineData("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: backup\n", "=twTO\n-----END PGP PRIVATE KEY BLOCK-----")]
    [InlineData("-----BEGIN PGP SECRET KEY BLOCK-----\nVersion: 2.6.3i\n", "-----END PGP SECRET KEY BLOCK-----")]
    [InlineData("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: \"rsa-key-20240926\"", "---- END SSH2 ENCRYPTED PRIVATE KEY ----")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,3F17F5316E2BAC89\n", "-----END RSA PRIVATE KEY-----")]
    public async Task ShouldRedactTheWholeBlock_WhenAPrivateKeyUsesAnotherArmor(string begin, string end)
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });

        var result = await rule.EvaluateAsync(CreateContext($"Key:\n{begin}\n{KeyBody(3)}\n{end}\nDone."));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be("Key:\n[SECRET_REDACTED]\nDone.");
    }

    [Theory]
    [InlineData("-----BEGIN PGP SECRET KEY BLOCK-----", "-----END PGP SECRET KEY BLOCK-----")]
    [InlineData("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "---- END SSH2 ENCRYPTED PRIVATE KEY ----")]
    public async Task ShouldBlock_WhenAPrivateKeyUsesAnotherArmor(string begin, string end)
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext($"{begin}\n{KeyBody(3)}\n{end}"));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("private-key");
    }

    // GitHub fine-grained personal access tokens: github_pat_ and 82 characters

    private const string FineGrainedToken =
        "github_pat_11AAAAAAA0bCdEfGhIjKlM_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";

    [Fact]
    public async Task ShouldBlock_WhenAFineGrainedGitHubTokenIsFound()
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext($"Use {FineGrainedToken} for the CI job."));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("github-token");
    }

    [Fact]
    public async Task ShouldRedactTheToken_WhenAFineGrainedGitHubTokenIsFound()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });

        var result = await rule.EvaluateAsync(CreateContext($"GITHUB_TOKEN={FineGrainedToken}\nnext line"));

        result.ModifiedText.Should().Be("GITHUB_TOKEN=[SECRET_REDACTED]\nnext line");
    }

    [Fact]
    public async Task ShouldPass_WhenAFineGrainedGitHubTokenIsTruncated()
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext("Tokens look like github_pat_11AAAAAAA0bCdEfGhIjKlM_... in the docs."));

        result.IsBlocked.Should().BeFalse();
    }

    // quoted secret fields: JSON, YAML flow maps, Python and JS literals

    [Theory]
    [InlineData("""{"api_key": "sk_live_1234567890abcdefghij"}""")]
    [InlineData("""{"user": "bob", "password":"hunter2!x"}""")]
    [InlineData("""{'secret': 'S3cr3tV@lue'}""")]
    [InlineData("""{"client_secret" : "abc123XYZ789def"}""")]
    [InlineData("""{"DB_PASSWORD": "Tr0ub4dor&3"}""")]
    [InlineData("""{"accessToken": "q9Xv2LmP8sKd"}""")]
    [InlineData("""{"token": "q9Xv2LmP8sKd"}""")]
    [InlineData("""config = {'signing_key': 'x7Qp9Lm2Vb4N'}""")]
    [InlineData("""$settings = ['password' => 'hunter2!x'];""")]
    public async Task ShouldBlock_WhenAQuotedFieldHoldsASecret(string text)
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("secret-field");
    }

    [Fact]
    public async Task ShouldRedactOnlyTheValue_WhenAQuotedFieldHoldsASecret()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });

        var result = await rule.EvaluateAsync(CreateContext(
            """{"user": "bob", "password": "hunter2!x", "nested": {'client_secret': 'S3cr3t\'V@lue'}}"""));

        result.ModifiedText.Should().Be(
            """{"user": "bob", "password": "[SECRET_REDACTED]", "nested": {'client_secret': '[SECRET_REDACTED]'}}""");
    }

    [Theory]
    [InlineData("""{"password": ""}""")]
    [InlineData("""{"password": "${DB_PASSWORD}"}""")]
    [InlineData("""{"password": "<password>"}""")]
    [InlineData("""{"password": "changeme"}""")]
    [InlineData("""{"api_key": "YOUR_API_KEY"}""")]
    [InlineData("""{"secret": "********"}""")]
    [InlineData("""{"secret": "short"}""")]
    [InlineData("""{"pwd": "/home/user/project"}""")]
    [InlineData("""{"client_secret": "https://vault.example.com/secrets/app"}""")]
    [InlineData("""{"next_page_token": "CAESBggCEAEYAQ"}""")]
    [InlineData("""{"token_type": "Bearer", "password_hint": "first pet"}""")]
    public async Task ShouldPass_WhenAQuotedFieldHoldsNoCredential(string text)
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    // connection-string URIs: the password, not the host, is the secret

    [Theory]
    [InlineData("postgres://user:pass@host/db", "connection-uri")]
    [InlineData("postgresql://app:S3cr3t@db.example.com:5432/app", "connection-uri")]
    [InlineData("mysql://root:toor@localhost:3306/mysql", "connection-uri")]
    [InlineData("mongodb://admin:hunter2@mongo:27017", "mongodb-uri")]
    [InlineData("mongodb+srv://admin:hunter2@cluster0.abc.mongodb.net/mydb", "mongodb-uri")]
    [InlineData("redis://:hunter2@redis.example.com:6379", "redis-uri")]
    [InlineData("rediss://default:hunter2@cache.example.com:6380", "redis-uri")]
    [InlineData("amqp://app:hunter2@rabbit:5672/vhost", "connection-uri")]
    [InlineData("ftp://anon:letmein@ftp.example.com/pub", "connection-uri")]
    [InlineData("sqlserver://sa:Str0ng!Pass@sql:1433;database=app", "connection-uri")]
    [InlineData("git clone https://ci:glpat-Xk9mP2vL7qR4tZ8w@gitlab.example.com/org/repo.git", "connection-uri")]
    public async Task ShouldBlock_WhenAUriCarriesAPassword(string text, string label)
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain(label);
    }

    [Theory]
    [InlineData("postgres://app:S3cr3t@db.example.com:5432/app", "postgres://app:[SECRET_REDACTED]@db.example.com:5432/app")]
    [InlineData("mongodb+srv://admin:hunter2@cluster0.abc.mongodb.net/mydb", "mongodb+srv://admin:[SECRET_REDACTED]@cluster0.abc.mongodb.net/mydb")]
    [InlineData("redis://:hunter2@redis.example.com:6379", "redis://:[SECRET_REDACTED]@redis.example.com:6379")]
    // a raw '@' in the password: the password runs to the last '@' before the host
    [InlineData("DATABASE_URL=postgres://u:p@ss@db:5432/app", "DATABASE_URL=postgres://u:[SECRET_REDACTED]@db:5432/app")]
    [InlineData("\"url\": \"amqp://app:hunter2@rabbit:5672/vhost\",", "\"url\": \"amqp://app:[SECRET_REDACTED]@rabbit:5672/vhost\",")]
    public async Task ShouldRedactOnlyThePassword_WhenAUriCarriesOne(string text, string expected)
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });

        var result = await rule.EvaluateAsync(CreateContext(text));

        result.ModifiedText.Should().Be(expected);
    }

    [Theory]
    [InlineData("See https://example.com/docs?page=2#auth for details.")]
    [InlineData("Connect to postgres://db.example.com:5432/app with your own credentials.")]
    [InlineData("Clone ssh://git@github.com/org/repo.git or https://user@example.com/repo.git")]
    [InlineData("Proxy at http://proxy.internal:3128/ and ftp://ftp.example.com:21/pub")]
    [InlineData("postgres://user:${DB_PASSWORD}@db:5432/app")]
    [InlineData("mysql://root:<password>@localhost/mysql")]
    [InlineData("redis://:****@cache:6379")]
    public async Task ShouldPass_WhenAUriCarriesNoPassword(string text)
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldRedactOnlyThePassword_WhenAConnectionStringCarriesOne()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Action = SecretAction.Redact });

        var result = await rule.EvaluateAsync(CreateContext(
            "Server=db.example.com;Database=app;User Id=admin;Password=s3cretP@ss!;Encrypt=true"));

        result.ModifiedText.Should().Be(
            "Server=db.example.com;Database=app;User Id=admin;Password=[SECRET_REDACTED];Encrypt=true");
    }

    [Fact]
    public async Task ShouldPass_WhenAConnectionStringPasswordIsAPlaceholder()
    {
        var result = await new SecretsDetectionRule().EvaluateAsync(CreateContext(
            "Server=db.example.com;Database=app;User Id=admin;Password=<your-password>;"));

        result.IsBlocked.Should().BeFalse();
    }

    // case-insensitive patterns must not depend on the process culture: under tr-TR, 'i' and 'I'
    // are not case variants of each other

    [Fact]
    public async Task ShouldDetectUppercaseKeyNames_WhenTheCurrentCultureIsTurkish()
    {
        var culture = CultureInfo.CurrentCulture;
        var uiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            CultureInfo.CurrentUICulture = new CultureInfo("tr-TR");

            // built under the Turkish culture, so its patterns are compiled under it too
            var rule = new SecretsDetectionRule(new SecretsDetectionOptions { Categories = SecretCategory.All });

            var assignment = await rule.EvaluateAsync(CreateContext("API_KEY=sk_live_1234567890abcdefghij"));
            var field = await rule.EvaluateAsync(CreateContext("""{"API_KEY": "q9Xv2LmP8sKd"}"""));
            var keyed = await rule.EvaluateAsync(CreateContext("CREDENTIALS=xK9mP2vL7qR4"));

            assignment.Reason.Should().Contain("api-key");
            field.Reason.Should().Contain("secret-field");
            keyed.Reason.Should().Contain("high-entropy-string");
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = uiCulture;
        }
    }

    [Fact]
    public void ShouldMatchCultureInvariantly_WhenAPatternIgnoresCase()
    {
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.All,
            CustomPatterns = new Dictionary<string, string> { ["internal-id"] = "(?i)internal_[0-9]{8}" }
        });

        var caseInsensitive = rule.Patterns
            .Where(p => p.Options.HasFlag(RegexOptions.IgnoreCase) || p.ToString().Contains("(?i", StringComparison.Ordinal))
            .ToList();

        caseInsensitive.Should().NotBeEmpty();
        caseInsensitive.Should().OnlyContain(p => p.Options.HasFlag(RegexOptions.CultureInvariant));
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

    // a secret after adversarial padding is still found: a pattern that backtracks over the padding
    // runs out of its match timeout and is skipped, which would miss it

    [Theory]
    [InlineData("jwt-run", "jwt-token")]
    [InlineData("connection-string-segments", "connection-string")]
    [InlineData("connection-string-servers", "connection-string")]
    [InlineData("mongodb-colons", "mongodb-uri")]
    [InlineData("uri-without-host", "connection-uri")]
    [InlineData("unterminated-quoted-value", "secret-field")]
    [InlineData("repeated-quoted-keys", "secret-field")]
    [InlineData("long-dash-rule", "private-key")]
    public async Task ShouldDetectTheSecret_WhenItFollowsAdversarialPadding(string kind, string label)
    {
        const string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        var text = kind switch
        {
            "jwt-run" => "x " + string.Concat(Enumerable.Repeat("eyJ", 100_000)) + " token " + jwt,
            "connection-string-segments" => string.Concat(Enumerable.Repeat("Host=a;", 50_000))
                + "\nServer=db;Database=app;Password=hunter2!",
            "connection-string-servers" => string.Concat(Enumerable.Repeat("Server=a;b=c;", 30_000))
                + "\nServer=db;Database=app;Password=hunter2!",
            "mongodb-colons" => "mongodb://" + string.Concat(Enumerable.Repeat("a:", 100_000))
                + " then mongodb://admin:hunter2@mongo:27017",
            "uri-without-host" => "postgres://u:" + new string('a', 200_000) + " then mysql://root:toor@db/app",
            "unterminated-quoted-value" => "{\"password\": \"" + new string('a', 200_000) + " {\"password\": \"hunter2!x\"}",
            "repeated-quoted-keys" => string.Concat(Enumerable.Repeat("\"password\":\"", 50_000)) + " {\"secret\": \"S3cr3tV@lue\"}",
            "long-dash-rule" => new string('-', 200_000) + $"\n-----BEGIN RSA PRIVATE KEY-----\n{SecretsDetectionRuleTests.KeyBody(2)}\n-----END RSA PRIVATE KEY-----",
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        var rule = new SecretsDetectionRule();

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Output });

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain(label);
    }
}
