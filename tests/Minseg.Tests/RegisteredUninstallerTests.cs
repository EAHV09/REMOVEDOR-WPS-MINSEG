using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public class RegisteredUninstallerTests
{
    private static readonly BinaryIdentity WpsUninstaller=new(@"C:\Apps\WPS\utility\uninst.exe","WPS Office","Kingsoft Corp. Ltd.","KUninstall.exe","WPS SOFTWARE PTE. LTD.",true,"BABCB4F52536500C40B884E58A6041D57CB5DF1860A9ADF22DC53C22A37C6FF4",100,0);
    [Fact]
    public void Official_Wps_12_uninstaller_publisher_is_recognized()
        =>RegisteredUninstaller.RequireIdentity(WpsUninstaller,Product.Wps);
    [Fact]
    public void Trust_failure_reports_Windows_code_and_file_instead_of_generic_identity_error()
    {
        var message=Assert.Throws<IOException>(()=>RegisteredUninstaller.RequireIdentity(WpsUninstaller with{SignatureValid=false,TrustStatus=unchecked((int)0x800B0109)},Product.Wps)).Message;
        Assert.Contains("0x800B0109",message);Assert.Contains(WpsUninstaller.Path,message);Assert.Contains("Windows no validó",message);
    }
    [Fact]
    public void Valid_but_unrelated_signer_is_not_reported_as_invalid_signature()
    {
        var message=Assert.Throws<IOException>(()=>RegisteredUninstaller.RequireIdentity(WpsUninstaller with{Signer="Unrelated Publisher"},Product.Wps)).Message;
        Assert.Contains("firma válida",message);Assert.Contains("Unrelated Publisher",message);
    }
    [Theory]
    [InlineData(@"C:\Program Files\Kingsoft\WPS Office\12.1\utility\uninst.exe /uninstall",@"C:\Program Files\Kingsoft\WPS Office\12.1\utility\uninst.exe")]
    [InlineData("\"C:\\WPS Office\\uninst.exe\" /quiet",@"C:\WPS Office\uninst.exe")]
    [InlineData(@"C:\folder.exe\WPS Office\uninst.exe",@"C:\folder.exe\WPS Office\uninst.exe")]
    public void Registered_path_is_resolved_for_explicit_file_launch(string command,string expected)
        =>Assert.Equal(expected,RegisteredUninstaller.Resolve(command));

    [Theory]
    [InlineData(@"C:\Program.exe Files\WPS\uninst.exe")]
    [InlineData(@"C:\WPS Office\uninst.exe.other")]
    [InlineData("\"C:\\WPS\\uninst.exe\"suffix")]
    [InlineData(@"\\server\share\uninst.exe")]
    [InlineData(@"uninst.exe /quiet")]
    [InlineData(@"C:\%MISSING_MINSEG_VARIABLE%\uninst.exe")]
    [InlineData("")]
    public void Ambiguous_nonlocal_or_incomplete_commands_are_rejected(string command)
        =>Assert.Throws<IOException>(()=>RegisteredUninstaller.Resolve(command));

    private static InstalledApp App(string view,bool machine=false,string version="12",string folder=@"C:\WPS Office")
        =>new(Product.Wps,"WPS Office",version,"Kingsoft",$"{(machine?"LocalMachine":"Users")}|{view}|Software\\Uninstall\\WPS",folder,folder+@"\uninst.exe",machine);
    [Fact]
    public void Mirrored_installation_is_processed_once()
        =>Assert.Single(InstalledPrograms.Deduplicate([App("Registry64"),App("Registry32")]));
    [Fact]
    public void Separate_versions_scopes_paths_and_keys_are_preserved()
    {
        var first=App("Registry64");
        Assert.Equal(5,InstalledPrograms.Deduplicate([first,App("Registry32",version:"13"),App("Registry32",machine:true),
            App("Registry32",folder:@"C:\Other WPS"),first with{RegistryPath=first.RegistryPath+"other"}]).Count);
    }
    [Fact]
    public void Remaining_alias_is_still_the_same_installation()
        =>Assert.True(InstalledPrograms.SameInstallation(App("Registry64"),App("Registry32")));
    [Fact]
    public void Remaining_key_with_changed_values_is_not_reported_removed()
    {
        var original=App("Registry64");
        var changed=App("Registry32",version:"13") with{UninstallCommand=@"C:\WPS\new.exe"};
        Assert.True(InstalledPrograms.SameRegistryEntry(original,changed));
        Assert.False(InstalledPrograms.SameInstallation(original,changed));
    }
    [Fact]
    public void Revalidation_prefers_exact_view_over_another_version()
    {
        var original=App("Registry64");
        Assert.Equal(original,InstalledPrograms.Revalidate(original,[original,App("Registry32",version:"13")]));
    }
    [Fact]
    public void Revalidation_uses_identical_alias_when_original_view_disappears()
    {
        var alias=App("Registry32");
        Assert.Equal(alias,InstalledPrograms.Revalidate(App("Registry64"),[alias]));
    }
    [Fact]
    public void Changed_remaining_entry_requires_a_new_scan()
        =>Assert.Throws<IOException>(()=>InstalledPrograms.Revalidate(App("Registry64"),[App("Registry32",version:"13")]));
    [Fact]
    public void Changed_original_view_does_not_fall_back_to_old_alias()
        =>Assert.Throws<IOException>(()=>InstalledPrograms.Revalidate(App("Registry64"),[App("Registry64",version:"13"),App("Registry32")]));
}
