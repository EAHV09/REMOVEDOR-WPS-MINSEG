using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public sealed class InstallationScanTests
{
    [Fact]
    public void NoScanCannotClaimProgramIsAbsent()
        =>Assert.Equal(InstallationState.Unknown,InstallationScan.State(null,Product.Wps));

    [Fact]
    public void DeniedRegistryReadCannotClaimProgramIsAbsent()
        =>Assert.Equal(InstallationState.Unknown,InstallationScan.State(new(DateTimeOffset.Now,[],[],["Acceso denegado"],false),Product.Wps));

    [Fact]
    public void PartialInventoryStillShowsTheInstallationsItFound()
    {
        var app=new InstalledApp(Product.AnyDesk,"AnyDesk","9","AnyDesk","HKLM/test",@"C:\Program Files\AnyDesk","",true);
        var scan=new ScanResult(DateTimeOffset.Now,[],[app],["Otro perfil sin acceso"],false);
        Assert.Equal(InstallationState.Found,InstallationScan.State(scan,Product.AnyDesk));
        Assert.Equal(InstallationState.Unknown,InstallationScan.State(scan,Product.Wps));
    }

    [Fact]
    public void CompletedEmptyInventoryMeansNoRegisteredInstall()
        =>Assert.Equal(InstallationState.NotFound,InstallationScan.State(new(DateTimeOffset.Now,[],[],[],true),Product.Wps));
}
