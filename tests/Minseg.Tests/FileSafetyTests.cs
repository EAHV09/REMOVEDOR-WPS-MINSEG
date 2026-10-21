using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class FileSafetyTests
{
    [Theory]
    [InlineData("\"C:\\Apps\\WPS\\uninst.exe\" /s & calc.exe",@"C:\Apps\WPS\uninst.exe")]
    [InlineData("powershell.exe -Command bad",null)]
    [InlineData("\"\\\\host\\share\\uninst.exe\"",null)]
    public void Only_a_local_executable_is_extracted_and_registry_arguments_are_discarded(string input,string? expected)
        =>Assert.Equal(expected,PathSafety.ExecutableFromCommand(input));
    [Fact(Skip="Prueba de laboratorio: este entorno no permite crear enlaces simbólicos (Win32 1314).")]
    public void Reparse_check_rejects_a_symbolic_link()
    {
        var root=Path.Combine(Path.GetTempPath(),"minseg-test-"+Guid.NewGuid());Directory.CreateDirectory(root);
        try
        {
            var data=Path.Combine(root,"original.txt");File.WriteAllText(data,"keep");
            var link=Path.Combine(root,"link.txt");
            try { File.CreateSymbolicLink(link,data); }
            catch(UnauthorizedAccessException) { return; }
            Assert.Throws<IOException>(()=>PathSafety.RequireNoReparse(link));
            Assert.Equal("keep",File.ReadAllText(data));
        }
        finally { Directory.Delete(root,true); }
    }
}
