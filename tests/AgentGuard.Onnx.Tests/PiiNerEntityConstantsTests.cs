using AgentGuard.Onnx;
using AgentGuard.Pii;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

public class PiiNerEntityConstantsTests
{
    [Fact]
    public void DefaultNerLabelMap_ShouldEmit_PiiEntitiesNerConstants()
    {
        // the NER recognizer's emitted entity types must stay in sync with the PiiEntities constants
        GlinerNerOptions.DefaultEntityLabelMap.Values
            .Should().BeEquivalentTo(new[]
            {
                PiiEntities.Person,
                PiiEntities.Location,
                PiiEntities.Organization,
                PiiEntities.DateTime,
            });
    }
}
