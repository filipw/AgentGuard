using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.Secrets;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class SecretsHighEntropyTests
{
    private static GuardrailContext CreateContext(string text) =>
        new() { Text = text, Phase = GuardrailPhase.Output };

    private static SecretsDetectionRule Rule(SecretAction action = SecretAction.Block, SecretCategory categories = SecretCategory.GenericHighEntropy) =>
        new(new SecretsDetectionOptions { Categories = categories, Action = action });

    // detections

    [Theory]
    [InlineData("Use aB3cD4eF5gH6iJ7kL8mN9oP0qR to sign in.", "Use [SECRET_REDACTED] to sign in.")]
    [InlineData("token: aB3cD4eF5gH6iJ7kL8mN9oP0qR", "token: [SECRET_REDACTED]")]
    [InlineData("first Zx8Qw2Lp5Nv7Rt3Ym6Kb9Hd4, then session=Jc5Tf8Wm2Qs7Xn4Lr9Pv3Gz6", "first [SECRET_REDACTED], then session=[SECRET_REDACTED]")]
    public async Task ShouldRedactTheToken_WhenAHighEntropyStringIsFoundInRedactMode(string text, string expected)
    {
        var result = await Rule(SecretAction.Redact).EvaluateAsync(CreateContext(text));

        result.IsModified.Should().BeTrue();
        result.Reason.Should().Contain("high-entropy-string");
        result.ModifiedText.Should().Be(expected);
    }

    [Theory]
    [InlineData("secret=9f86d081884c7d659a2feaa0c55ad015")]
    [InlineData("auth_token: 3f7a9c2e1b8d4f6a9e2c7d1a4b6c8e0f")]
    [InlineData("\"signing_key\": \"A3F1C9E27B4D8F6012E5C7A9B3D1F4E8\"")]
    [InlineData("PRIVATE_KEY=0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")]
    public async Task ShouldDetect_WhenAHexSecretIsAssignedToASecretLikeKey(string text)
    {
        var result = await Rule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("high-entropy-string");
    }

    [Theory]
    [InlineData("password=Xk9mP2vL7q!z")]
    [InlineData("API_KEY: q9Xv2LmP8sKd")]
    [InlineData("db_pwd = 'Zr8#nW2qLx5v'")]
    [InlineData("x-auth: Hq7Lm2Pz9Wd4")]
    [InlineData("credential=xK9mP2vL7qR4")]
    [InlineData("\"apikey\": \"Rt5Yv8Nq2Mz6\"")]
    [InlineData("totp_secret: JBSWY3DPEHPK3PXP")]
    [InlineData("GET https://api.example.com/v1/data?api_key=Rt5Yv8Nq2Mz6Lp3K")]
    public async Task ShouldDetect_WhenAShortTokenIsAssignedToASecretLikeKey(string text)
    {
        var result = await Rule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("high-entropy-string");
    }

    [Fact]
    public async Task ShouldRedactOnlyTheValue_WhenAShortTokenIsAssignedToASecretLikeKey()
    {
        var result = await Rule(SecretAction.Redact).EvaluateAsync(CreateContext("export DB_PASSWORD=Xk9mP2vL7q!z\nexport DB_HOST=db"));

        result.ModifiedText.Should().Be("export DB_PASSWORD=[SECRET_REDACTED]\nexport DB_HOST=db");
    }

    [Theory]
    [InlineData("The build tag is Xk9mP2vL7qR4 today.")]
    [InlineData("password=changeme1234")]
    [InlineData("api_key: YourApiKeyHere")]
    [InlineData("token = ${GITHUB_TOKEN}")]
    [InlineData("secret: /run/secrets/db_password")]
    [InlineData("key: node-role.kubernetes.io/control-plane")]
    [InlineData("token: 1234567890123")]
    public async Task ShouldPass_WhenAShortValueIsNotARandomSecret(string text)
    {
        var result = await Rule().EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    // false positives: none of these is a secret, with every category enabled

    [Theory]
    [InlineData("Fixed in commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b, reverted in 3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f.")]
    [InlineData("git log shows e83c5163316f89bfbde7d9ab23ca2e25604af290 as the first commit.")]
    public async Task ShouldPass_WhenGitShasAppearInProse(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("Order 123e4567-e89b-12d3-a456-426614174000 shipped.")]
    [InlineData("idempotency_key: 3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    [InlineData("{\"request_id\": \"7D9C0E2F-0E5E-4C62-9A3F-6AD1A4E1B2C3\"}")]
    public async Task ShouldPass_WhenUuidsAppear(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")]
    [InlineData("MD5 checksum = 5d41402abc4b2a76b9719d911017c592")]
    [InlineData("<script src=\"app.js\" integrity=\"sha384-Hn2kIRyYInQwFLKi6mjnAT84Xme0c9mofnKuYR9kBAmoYgPFOeRULUcD7nYNIT/S\"></script>")]
    [InlineData("\"integrity\": \"sha512-WWBGtyfDRrPIzxFy0HaPccRrj678i95zax2MixXJQT5RTkjHJJWsd/YhWwqy4EaG9POVDAK/RjxiWi0jaoAHnA==\"")]
    [InlineData("digest: -iyMxPKBdrvu1Lc231aaNMec03I-nsQvlnS01GrGuLg")]
    public async Task ShouldPass_WhenHashesAreQuoted(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\">")]
    [InlineData("url(data:application/octet-stream;base64,T2Zx8Qw2Lp5Nv7Rt3Ym6Kb9Hd4Jc5Tf8Wm2Qs7Xn4Lr9Pv3Gz6Ua1Ek0Iy)")]
    [InlineData("{\"thumbnail\": \"/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/\"}")]
    [InlineData("{\"logo\": \"R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7\"}")]
    public async Task ShouldPass_WhenTheTextCarriesBase64ImagesOrDataUris(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("Pneumonoultramicroscopicsilicovolcanoconiosis and floccinaucinihilipilification are long words.")]
    [InlineData("QuickBrownFoxJumpsOverTheLazyDog is a pangram in PascalCase.")]
    [InlineData("Register AbstractSingletonProxyFactoryBean before getUserAccountSettingsHandler runs.")]
    [InlineData("Call HttpClientHandler_DangerousAcceptAnyServerCertificateValidator in tests only.")]
    [InlineData("Set get_user_account_settings_handler and AGENTGUARD_ONNX_MODEL_PATH, then XMLHttpRequestEventTarget.")]
    public async Task ShouldPass_WhenTheTextHasLongWordsOrIdentifiers(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("Installed to /usr/local/lib/python3.11/site-packages/requests/adapters.py")]
    [InlineData("See src/AgentGuard.Core/Rules/Secrets/SecretsDetectionRule.cs for details.")]
    [InlineData("Credentials are read from ~/.config/gcloud/application_default_credentials.json")]
    [InlineData("Layer at /var/lib/docker/overlay2/3f7a9c2e1b8d4f6a9e2c7d1a4b6c8e0f/merged")]
    [InlineData("Open C:\\Users\\filip\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe")]
    public async Task ShouldPass_WhenTheTextHasFilePaths(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("Shared at https://drive.google.com/file/d/1aB3cD4eF5gH6iJ7kL8mN9oP0qRsTuVwXyZ/view?usp=sharing")]
    [InlineData("Watch https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG")]
    [InlineData("Build log: https://github.com/org/repo/actions/runs/11062418331/job/30738115260#step:4:12")]
    public async Task ShouldPass_WhenAUrlCarriesNoCredentials(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    // a JWT is flagged only when the JWT pattern accepts it; JWT-like strings in docs are not
    // random tokens

    [Theory]
    [InlineData("A token looks like eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.<signature>")]
    [InlineData("An unsigned header and empty claims: eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo")]
    [InlineData("The header eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9 names the key.")]
    public async Task ShouldPass_WhenAJwtLikeStringIsNotARealJwt(string text)
    {
        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext(text));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldReportARealJwtOnlyAsAJwt_WhenEveryCategoryIsEnabled()
    {
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        var result = await Rule(categories: SecretCategory.All).EvaluateAsync(CreateContext($"Your token: {jwt}"));

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["detectedCategories"].Should().BeEquivalentTo(new[] { "jwt-token" });
    }
}

// scans large inputs on purpose, so it runs in the non-parallel large-input collection
[Collection(LargeInputTestGroup.Name)]
public class SecretsHighEntropyLargeInputTests
{
    [Theory]
    [InlineData("identifiers")]
    [InlineData("key-names")]
    [InlineData("name-characters")]
    [InlineData("urls")]
    public async Task ShouldDetectTheSecret_WhenItFollowsLargePadding(string kind)
    {
        var padding = kind switch
        {
            "identifiers" => string.Concat(Enumerable.Repeat("getUserAccountSettingsHandler 9f86d081884c7d659a2feaa0c55ad015 ", 20_000)),
            "key-names" => string.Concat(Enumerable.Repeat("password: key= token: ", 40_000)),
            "name-characters" => new string('a', 500_000) + " " + string.Concat(Enumerable.Repeat("a.", 200_000)),
            "urls" => string.Concat(Enumerable.Repeat("https://example.com/a/b?c=d ", 30_000)),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.GenericHighEntropy,
            Action = SecretAction.Redact
        });

        var result = await rule.EvaluateAsync(new GuardrailContext
        {
            Text = padding + "\npassword=Xk9mP2vL7q!z",
            Phase = GuardrailPhase.Output
        });

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().EndWith("\npassword=[SECRET_REDACTED]");
    }

    // a line far too long to scan inside the match timeout costs only its own chunk of the text, so
    // the secret on the next line is still found
    [Fact]
    public async Task ShouldDetectTheSecret_WhenAnEarlierLineIsTooLongToScanInTime()
    {
        var longLine = string.Concat(Enumerable.Repeat("getUserAccountSettingsHandler 9f86d081884c7d659a2feaa0c55ad015 ", 190_000));
        var rule = new SecretsDetectionRule(new SecretsDetectionOptions
        {
            Categories = SecretCategory.GenericHighEntropy,
            Action = SecretAction.Redact
        });

        var result = await rule.EvaluateAsync(new GuardrailContext
        {
            Text = longLine + "\npassword=Xk9mP2vL7q!z",
            Phase = GuardrailPhase.Output
        });

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().EndWith("\npassword=[SECRET_REDACTED]");
    }
}
