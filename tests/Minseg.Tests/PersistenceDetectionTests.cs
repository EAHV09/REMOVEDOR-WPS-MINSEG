using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class PersistenceDetectionTests
{
    [Fact] public void Signed_renamed_target_is_detected_without_file_scan()
    {
        var id=new BinaryIdentity(@"C:\Tools\support.exe","AnyDesk","AnyDesk","AnyDesk.exe","AnyDesk Software GmbH",true,new string('A',64),100);
        var f=PersistenceTarget.Classify("Remote helper",id.Path,id);
        Assert.NotNull(f);Assert.Equal(Product.AnyDesk,f.Product);Assert.Equal(Trust.Confirmed,f.Trust);
    }
    [Fact] public void Name_alone_cannot_authorize_cleanup()
    {
        var f=PersistenceTarget.Classify("WPS Update",@"C:\missing\setup.exe",null);
        Assert.NotNull(f);Assert.Equal(Trust.Review,f.Trust);Assert.Null(f.Identity);
        Assert.Null(PersistenceTarget.Classify("Microsoft Copilot",@"C:\Windows\Copilot.exe",null));
    }
    [Fact] public void Partial_scan_never_claims_absence()
    {
        var report=new PersistenceReport(DateTimeOffset.Now,[],["Acceso denegado"],false);
        Assert.Contains("incompleto",report.Summary(Product.Wps),StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Sin persistencia",report.Summary(Product.Wps));
    }
    [Fact] public void Confirmed_and_review_items_are_distinct()
    {
        var a=new Finding(Product.Wps,FindingKind.Startup,"a","a",Trust.Confirmed,"");
        var report=new PersistenceReport(DateTimeOffset.Now,[a,a with{Trust=Trust.Review}],[],true);
        Assert.Contains("1 comprobada",report.Summary(Product.Wps));Assert.Contains("1 por revisar",report.Summary(Product.Wps));
        Assert.Contains("alcance",report.Summary(Product.AnyDesk));
    }
    [Fact] public void Operator_environment_cannot_confirm_another_users_startup_target()
    {
        var admin=new BinaryIdentity(@"C:\Users\Admin\AppData\Local\AnyDesk\AnyDesk.exe","AnyDesk","AnyDesk","AnyDesk.exe","AnyDesk Software GmbH",true,new string('A',64),100);
        var command=@"""%LOCALAPPDATA%\AnyDesk\AnyDesk.exe""";
        Assert.Equal(Trust.Review,PersistenceTarget.Classify("AnyDesk",command,admin)!.Trust);
        Assert.Equal(Trust.Review,PersistenceTarget.Classify("AnyDesk",command,admin with{Path=@"C:\Users\Other\AppData\Local\AnyDesk\AnyDesk.exe",SignatureValid=false})!.Trust);
    }
    [Fact] public void Native_Run_locations_round_trip_to_cleaner_validation()
    {
        var device=new DeviceInfo("test","Windows","x64","User","S-1-5-21-123",@"C:\Users\User","User",false,1,[]);
        foreach(bool machine in new[]{true,false})
        {
            var item=new Finding(Product.AnyDesk,FindingKind.Startup,"AnyDesk",(machine?"Machine":"User")+"|"+PersistenceLocation.RunKey(machine,device.UserSid)+"|AnyDesk",Trust.Confirmed,"");
            Assert.Equal(3,PersistenceCleaner.ValidateStartupLocation(item,device).Length);
            Assert.Throws<IOException>(()=>PersistenceCleaner.ValidateStartupLocation(item with{Location=item.Location.Replace("CurrentVersion\\Run|","CurrentVersion\\RunOnce|")},device));
        }
    }
}
