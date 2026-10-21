using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class ResidueTests
{
    private static BinaryIdentity Anchor(string path)=>new(path,"AnyDesk","AnyDesk","AnyDesk.exe","AnyDesk Software GmbH",true,new string('A',64),100);
    [Fact]
    public void Only_technical_files_next_to_a_confirmed_product_binary_are_eligible()
    {
        var anchor=Anchor(@"C:\ProgramData\AnyDesk\AnyDesk.exe");
        Assert.True(ResidueRules.Eligible(@"C:\ProgramData\AnyDesk\service.conf",anchor,Product.AnyDesk));
        Assert.False(ResidueRules.Eligible(@"C:\ProgramData\AnyDesk\reporte.docx",anchor,Product.AnyDesk));
        Assert.False(ResidueRules.Eligible(@"C:\ProgramData\AnyDesk\connection_trace.txt",anchor,Product.AnyDesk));
        Assert.False(ResidueRules.Eligible(@"C:\ProgramData\OtraApp\service.conf",anchor,Product.AnyDesk));
        Assert.False(ResidueRules.Eligible(@"C:\ProgramData\AnyDesk\backup\service.conf",anchor,Product.AnyDesk));
    }
    [Fact]
    public void Shared_downloads_folder_is_never_swept()
    {
        var anchor=Anchor(@"C:\Users\Ana\Downloads\AnyDesk.exe");
        Assert.False(ResidueRules.Eligible(@"C:\Users\Ana\Downloads\service.conf",anchor,Product.AnyDesk));
    }
}
