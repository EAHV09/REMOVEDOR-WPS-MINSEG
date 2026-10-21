using System.Security.Cryptography;
using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class CleanupTests
{
    [Fact]
    public void Cleanup_preserves_exact_bytes_before_deleting_the_selected_file()
    {
        using var fixture=new Fixture();var file=Path.Combine(fixture.Root,"cache.tmp");File.WriteAllText(file,"sample");
        var hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
        var saved=SafeFileCleaner.PreserveAndDelete(file,hash,fixture.Backup);
        Assert.False(File.Exists(file));Assert.Equal("sample",File.ReadAllText(saved));
    }
    [Fact]
    public void File_changed_after_scan_is_not_deleted()
    {
        using var fixture=new Fixture();var file=Path.Combine(fixture.Root,"cache.tmp");File.WriteAllText(file,"new data");
        Assert.Throws<IOException>(()=>SafeFileCleaner.PreserveAndDelete(file,new string('0',64),fixture.Backup));
        Assert.Equal("new data",File.ReadAllText(file));
    }
    [Fact]
    public void Personal_document_cannot_be_deleted_even_with_the_correct_hash()
    {
        using var fixture=new Fixture();var file=Path.Combine(fixture.Root,"report.docx");File.WriteAllText(file,"keep");
        var hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
        Assert.Throws<IOException>(()=>SafeFileCleaner.PreserveAndDelete(file,hash,fixture.Backup));
        Assert.True(File.Exists(file));
    }
    private sealed class Fixture:IDisposable
    {
        public string Root{get;}=Path.Combine(Path.GetTempPath(),"minseg-clean-test-"+Guid.NewGuid());
        public string Backup=>Path.Combine(Root,"vault");
        public Fixture(){Directory.CreateDirectory(Backup);}
        public void Dispose(){Directory.Delete(Root,true);}
    }
}
