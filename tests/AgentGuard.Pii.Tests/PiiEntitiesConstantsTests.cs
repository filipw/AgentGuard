using System.Reflection;
using AgentGuard.Pii;
using AgentGuard.Pii.Analyzer;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class PiiEntitiesConstantsTests
{
    private static readonly string[] NerEntities =
        [PiiEntities.Person, PiiEntities.Location, PiiEntities.Organization, PiiEntities.DateTime];

    private static List<string> AllEntityConstants() =>
        typeof(PiiEntities).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f is { IsLiteral: true } && f.FieldType == typeof(string))
            .Select(f => (string)f.GetValue(null)!)
            .ToList();

    [Fact]
    public void RegexAndChecksumConstants_ShouldExactlyMatch_AllRecognizerEntities()
    {
        // build every always-on + opt-in pack so the registry exposes the full regex/checksum vocabulary
        var registry = PiiRecognizers.CreateRegistry(
            "en", [PiiCountries.Uk, PiiCountries.De, PiiCountries.In, PiiCountries.It, PiiCountries.Es]);
        var supported = registry.GetSupportedEntities("en");

        var nonNerConstants = AllEntityConstants().Where(c => !NerEntities.Contains(c));

        // guards drift in BOTH directions: a new recognizer entity with no constant, or a constant
        // that no recognizer actually produces, fails this test.
        nonNerConstants.Should().BeEquivalentTo(supported);
    }

    [Fact]
    public void Constants_ShouldBeUnique_AndUpperSnakeCase()
    {
        var all = AllEntityConstants();

        all.Should().OnlyHaveUniqueItems();
        all.Should().AllSatisfy(c => c.Should().MatchRegex("^[A-Z][A-Z0-9_]*$"));
    }
}
