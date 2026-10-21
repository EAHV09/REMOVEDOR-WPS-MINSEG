using Minseg.Core;
using System.Security.Cryptography;
using Xunit;
namespace Minseg.Tests;

public sealed class KingsoftDataTests:IDisposable
{
    private readonly string temp=Path.Combine(Path.GetTempPath(),"minseg-data-"+Guid.NewGuid());
    private string Root=>Path.Combine(temp,"Documents","KingsoftData");
    public KingsoftDataTests()=>Directory.CreateDirectory(Root);
    [Fact]
    public void Folder_retained_only_for_documents_is_not_reported_as_a_cleanup_failure()
    {
        var path=Path.Combine(Root,"contrato.docx");File.WriteAllText(path,"conservar");
        var findings=new List<Finding>();var warnings=new List<string>();
        KingsoftDataResources.Add(Root,findings,warnings,()=>true);
        Assert.DoesNotContain(findings,f=>f.Kind==FindingKind.Directory);
        Assert.All(findings,f=>Assert.Equal(Trust.Protected,f.Trust));Assert.Empty(warnings);
        Assert.Equal("conservar",File.ReadAllText(path));
    }
    [Fact]
    public void Hidden_empty_technical_folders_are_removed_but_documents_stay_byte_identical()
    {
        var folder=Path.Combine(Root,"office6","KingsoftUE");Directory.CreateDirectory(folder);
        File.SetAttributes(folder,File.GetAttributes(folder)|FileAttributes.Hidden);
        var document=Path.Combine(Root,"contrato.docx");File.WriteAllBytes(document,[0x50,0x4b,1,2,3]);
        Assert.True(SafeFileCleaner.DeleteEmptyDirectory(folder,Root));
        Assert.False(Directory.Exists(folder));
        Assert.False(SafeFileCleaner.DeleteEmptyDirectory(Root,Root));
        Assert.Equal(new byte[]{0x50,0x4b,1,2,3},File.ReadAllBytes(document));
    }
    [Fact]
    public void Empty_directory_exception_cannot_remove_Documents_or_cloud_or_unrelated_folders()
    {
        foreach(var relative in new[]{"Documents","Documents\\KingsoftData-other","OneDrive\\Documents\\KingsoftData"})
        {
            var path=Path.Combine(temp,relative);Directory.CreateDirectory(path);
            Assert.ThrowsAny<IOException>(()=>SafeFileCleaner.DeleteEmptyDirectory(path,path));
        }
    }
    [Fact]
    public void Known_font_resource_is_backed_up_but_document_disguised_as_font_is_preserved()
    {
        var folder=Path.Combine(Root,"office6","mtfont");Directory.CreateDirectory(folder);
        var backup=Path.Combine(temp,"vault");Directory.CreateDirectory(backup);
        var file=Path.Combine(folder,"math.ttf");
        // Minimal sfnt header with one bounded table. This is a resource, not a document extension.
        byte[] font=new byte[32];font[1]=1;font[5]=1;font[12]=(byte)'n';font[13]=(byte)'a';font[14]=(byte)'m';font[15]=(byte)'e';font[23]=28;font[27]=4;
        File.WriteAllBytes(file,font);
        var saved=SafeFileCleaner.PreserveAndDeleteKingsoftResource(file,Hash(font),backup,Root);
        Assert.False(File.Exists(file));Assert.Equal(font,File.ReadAllBytes(saved));
        File.WriteAllText(file,"Mi documento sin guardar");
        Assert.ThrowsAny<IOException>(()=>SafeFileCleaner.PreserveAndDeleteKingsoftResource(file,Hash(File.ReadAllBytes(file)),backup,Root));
        Assert.Equal("Mi documento sin guardar",File.ReadAllText(file));
    }
    [Theory]
    [InlineData("contrato.docx")][InlineData("recovery.tmp")][InlineData("datos.db")][InlineData("ecuacion.xml")]
    public void Documents_and_unknown_files_inside_technical_folders_are_not_deleted(string name)
    {
        var file=Path.Combine(Root,"office6","omath",name);Directory.CreateDirectory(Path.GetDirectoryName(file)!);File.WriteAllText(file,"conservar");
        var backup=Path.Combine(temp,"vault");Directory.CreateDirectory(backup);
        Assert.ThrowsAny<IOException>(()=>SafeFileCleaner.PreserveAndDeleteKingsoftResource(file,Hash(File.ReadAllBytes(file)),backup,Root));
        Assert.Equal("conservar",File.ReadAllText(file));
    }
    private static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes));
    public void Dispose()=>Directory.Delete(temp,true);
}
