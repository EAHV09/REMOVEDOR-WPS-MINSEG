using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class HistoricalPersistenceTests
{
    private static Finding Orphan()
    {
        var path=Path.Combine(Path.GetTempPath(),"MINSEG-absent-"+Guid.NewGuid().ToString("N"),"AnyDesk.exe");
        var identity=new BinaryIdentity(path,"AnyDesk","AnyDesk","AnyDesk.exe","AnyDesk Software GmbH",true,new string('A',64),100);
        return new(Product.AnyDesk,FindingKind.Task,"AnyDesk","\\AnyDesk",Trust.Confirmed,"",identity,path,PersistenceSnapshot.Hash("original"));
    }
    [Fact]
    public void Reviewed_orphan_cannot_be_promoted_by_repeating_a_scan()
    {
        var item=Orphan();var previous=new ScanResult(DateTimeOffset.Now,[item with{Trust=Trust.Review}],[],[],true);
        Assert.Equal(Trust.Review,PersistenceScanner.Snapshot(item,"original",previous).Trust);
    }
    [Fact]
    public void Unchanged_confirmed_orphan_can_be_cleaned_but_modified_definition_cannot()
    {
        var item=Orphan();var previous=new ScanResult(DateTimeOffset.Now,[item],[],[],true);
        Assert.Equal(Trust.Confirmed,PersistenceScanner.Snapshot(item,"original",previous).Trust);
        Assert.Equal(Trust.Review,PersistenceScanner.Snapshot(item,"changed arguments",previous).Trust);
    }
    [Fact]
    public void Historical_identity_must_also_match()
    {
        var item=Orphan();var previous=new ScanResult(DateTimeOffset.Now,[item with{Identity=item.Identity! with{Sha256=new string('B',64)}}],[],[],true);
        Assert.Equal(Trust.Review,PersistenceScanner.Snapshot(item,"original",previous).Trust);
    }
}
