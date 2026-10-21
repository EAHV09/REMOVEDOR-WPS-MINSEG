using Minseg.Core;
using Xunit;

namespace Minseg.Tests;

public class SafetyTests
{
    [Theory]
    [InlineData(true,"WPS SOFTWARE PTE. LTD.","WPS Office",true)]
    [InlineData(false,"WPS SOFTWARE PTE. LTD.","WPS Office",false)]
    [InlineData(true,"FAKE WPS SOFTWARE PTE. LTD.","WPS Office",false)]
    [InlineData(true,"WPS SOFTWARE PTE. LTD.","Unrelated product",false)]
    public void Current_official_Wps_publisher_requires_a_valid_signature_and_matching_product(bool valid,string signer,string product,bool expected)
    {
        var file=new BinaryIdentity(@"C:\Apps\WPS Office\utility\uninst.exe",product,"Kingsoft Corp. Ltd.","",signer,valid,new string('A',64),200);
        Assert.Equal(expected,SafetyRules.Identify(file)==Product.Wps);
    }
    // A prefix-only path check would allow deletion in a neighboring folder.
    [Theory]
    [InlineData(@"C:\Apps\WPS", @"C:\Apps\WPS\bin\wps.exe", true)]
    [InlineData(@"C:\Apps\WPS", @"C:\Apps\WPS-other\data.txt", false)]
    [InlineData(@"C:\Apps\WPS", @"C:\Apps\WPS\..\Office\winword.exe", false)]
    [InlineData(@"C:\Apps\WPS", @"C:\Apps\WPS", false)]
    [InlineData(@"C:\", @"C:\Windows\explorer.exe", false)]
    [InlineData(@"C:\Apps\WPS", @"C:\Apps\WPS\wps.exe:other", false)]
    [InlineData(@"C:\Apps\WPS", @"\\server\share\wps.exe", false)]
    public void Containment_rejects_escape_root_and_streams(string root, string candidate, bool expected)
        => Assert.Equal(expected, SafetyRules.IsContained(root, candidate));

    [Theory]
    [InlineData(@"C:\Apps\WPS\report.docx")]
    [InlineData(@"C:\Apps\WPS\backup\cache.bin")]
    [InlineData(@"C:\Users\u\WPSDrive\anything.exe")]
    [InlineData(@"C:\Users\u\OneDrive\setup.exe")]
    [InlineData(@"C:\Apps\AnyDesk\recording.anydesk")]
    public void User_files_are_preserved_even_inside_a_product_folder(string path)
        => Assert.True(SafetyRules.IsPersonalData(path));

    [Fact]
    public void A_file_name_alone_never_authorizes_cleanup()
    {
        var file = new BinaryIdentity(@"C:\Temp\AnyDesk.exe", "", "", "", "", false, new string('A',64), 200);
        Assert.Null(SafetyRules.Identify(file));
        Assert.False(SafetyRules.CanClean(file, Product.AnyDesk));
    }

    [Fact]
    public void A_renamed_valid_AnyDesk_binary_is_identified_by_signed_metadata()
    {
        var file = new BinaryIdentity(@"C:\Temp\support123.exe", "AnyDesk", "AnyDesk Software GmbH",
            "AnyDesk.exe", "AnyDesk Software GmbH", true, new string('A',64), 200);
        Assert.Equal(Product.AnyDesk, SafetyRules.Identify(file));
        Assert.True(SafetyRules.CanClean(file, Product.AnyDesk));
    }

    [Fact]
    public void Invalid_signature_and_unrelated_Kingsoft_products_do_not_authorize_cleanup()
    {
        var bad = new BinaryIdentity(@"C:\Apps\WPS\wps.exe", "WPS Office", "Kingsoft", "wps.exe",
            "Kingsoft Office Software Corporation Limited", false, new string('A',64), 200);
        Assert.False(SafetyRules.CanClean(bad, Product.Wps));
        Assert.Null(SafetyRules.Identify(bad with { SignatureValid=true, ProductName="Kingsoft Antivirus" }));
    }

    [Fact]
    public void Office_Copilot_and_Explorer_are_never_cleanup_targets()
    {
        foreach(var name in new[]{"winword.exe","excel.exe","powerpnt.exe","copilot.exe","explorer.exe"})
        {
            var file=new BinaryIdentity(@"C:\Program Files\Microsoft\"+name,"WPS Office","Kingsoft",name,
                "Kingsoft Office Software Corporation Limited",true,new string('A',64),200);
            Assert.False(SafetyRules.CanClean(file,Product.Wps));
        }
    }

    [Fact]
    public void MSI_arguments_disable_restart_and_application_shutdown()
    {
        var command=SafetyRules.MsiUninstall("{B181A235-BF50-42DA-BFA3-458078074F25}");
        Assert.Contains("/norestart",command.Arguments);
        Assert.Contains("REBOOT=ReallySuppress",command.Arguments);
        Assert.Contains("MSIRESTARTMANAGERCONTROL=Disable",command.Arguments);
        Assert.Equal("/x",command.Arguments[0]);
    }

    [Theory]
    [InlineData("{bad} & calc.exe")]
    [InlineData("/i C:\\other.msi")]
    public void MSI_command_injection_is_rejected(string text)
        => Assert.Throws<ArgumentException>(()=>SafetyRules.MsiUninstall(text));
}
