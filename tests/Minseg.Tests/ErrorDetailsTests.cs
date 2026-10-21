using System.Runtime.InteropServices;
using Minseg.Core;
using Xunit;

namespace Minseg.Tests;

public sealed class ErrorDetailsTests
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptyWindowsErrorStillExplainsFailure(string message)
    {
        var result=ErrorDetails.Message(new COMException(message,unchecked((int)0x80070005)));
        Assert.False(string.IsNullOrWhiteSpace(result));
        Assert.Contains("80070005",result);
    }

    [Fact]
    public void EmptyWrapperUsesUsefulInnerMessage()
    {
        var result=ErrorDetails.Message(new Exception("",new IOException("El archivo está ocupado.")));
        Assert.Contains("El archivo está ocupado.",result);
    }

    [Fact]
    public void ExistingUsefulMessageIsPreserved()
        =>Assert.Contains("Guarda tus documentos",ErrorDetails.Message(new InvalidOperationException("Guarda tus documentos")));
}
