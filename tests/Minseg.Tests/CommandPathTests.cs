using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class CommandPathTests
{
    [Theory]
    [InlineData(@"C:\Program Files\AnyDesk\AnyDesk.exe --service")]
    [InlineData(@"C:\Tools\AnyDesk.exe.other --start")]
    [InlineData(@"C:\folder.exe\tool.other --start")]
    [InlineData("\"C:\\Tools\\AnyDesk.exe\"suffix")]
    public void Ambiguous_or_partial_executable_is_not_trusted(string command)=>Assert.Null(PathSafety.ExecutableFromCommand(command));
    [Theory]
    [InlineData("\"C:\\Program Files\\AnyDesk\\AnyDesk.exe\" --service",@"C:\Program Files\AnyDesk\AnyDesk.exe")]
    [InlineData(@"C:\folder.exe\real.exe --start",@"C:\folder.exe\real.exe")]
    [InlineData(@"C:\Tools\AnyDesk.exe --start",@"C:\Tools\AnyDesk.exe")]
    public void Complete_executable_token_is_preserved(string command,string expected)=>Assert.Equal(expected,PathSafety.ExecutableFromCommand(command));
}
