using Minseg.Core;
using System.Text.Json;
using Xunit;
namespace Minseg.Tests;
public class ExplorerEvidenceTests
{
    [Fact]
    public void Snapshot_of_a_different_application_cannot_authorize_a_WPS_edit()
    {
        var unchanged=JsonSerializer.Serialize(new{Name="",Kind="String",Value="WPSOffice.docx.6"});
        var changed=JsonSerializer.Serialize(new{Name="",Kind="String",Value="Word.Document.12"});
        Assert.True(ExplorerResidues.MatchesSnapshot(unchanged,"WPSOffice.docx.6"));
        Assert.False(ExplorerResidues.MatchesSnapshot(changed,"WPSOffice.docx.6"));
    }
    [Fact]
    public void Preuninstall_evidence_survives_missing_identity_only_for_same_value_location_and_hash()
    {
        var content=JsonSerializer.Serialize(new{Name="",Kind="String",Value="{AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB}"});
        var edit=new ExplorerEdit(true,@".docx\shellex\"+ExplorerRepair.Preview,"","{AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB}",null);
        var location=@"UserClasses|S-1-5-21-1|.docx\shellex\"+ExplorerRepair.Preview+"|";
        var finding=new Finding(Product.Wps,FindingKind.Registry,"preview",location,Trust.Confirmed,"",Reference:ExplorerResidues.Marker+JsonSerializer.Serialize(edit),ContentHash:RegistryResidues.Hash(content));
        Assert.True(ExplorerResidues.CanReuse(finding,location,content));
        Assert.False(ExplorerResidues.CanReuse(finding,location+"other",content));
        Assert.False(ExplorerResidues.CanReuse(finding,location,content.Replace("AAAAAAAA","EEEEEEEE")));
        Assert.False(ExplorerResidues.CanReuse(finding with{Trust=Trust.Review},location,content));
    }
}
