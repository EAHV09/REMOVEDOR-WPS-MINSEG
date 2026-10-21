using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class ProductScanPlanTests
{
    [Fact]
    public void Focused_report_does_not_claim_unselected_product_is_clear()
    {
        var products=new HashSet<Product>{Product.Wps};
        var scan=new ScanResult(DateTimeOffset.Now,[],[],[],true,ProductScanPlan.Coverage,products);
        var result=new RemovalResult(scan,scan,new HashSet<Product>(),new HashSet<Product>());
        Assert.True(result.VerifiedClear(Product.Wps));Assert.False(result.VerifiedClear(Product.AnyDesk));
        Assert.Equal("Fuera de esta revisión",new PersistenceReport(scan.CapturedAt,[],[],true,scan.Scope,products).Summary(Product.AnyDesk));
    }
    [Theory]
    [InlineData("WPSCloud","\"C:\\Apps\\WPS\\cloud.exe\"",true)]
    [InlineData("Updater","\"C:\\Apps\\WPS\\renamed.exe\"",true)]
    [InlineData("Other","\"C:\\Apps\\Other\\app.exe\"",false)]
    [InlineData("AnyDesk","\"C:\\Apps\\AnyDesk\\AnyDesk.exe\"",false)]
    public void Focused_persistence_uses_product_name_or_contained_executable(string name,string command,bool expected)
        =>Assert.Equal(expected,PersistenceTarget.Related(name,command,new HashSet<Product>{Product.Wps},[@"C:\Apps\WPS"]));
    private static readonly DeviceInfo Device=new("test","Windows","X64","user","sid",@"C:\Users\test","user",false,1,[]);
    [Fact]
    public void Direct_scan_uses_selected_product_roots_without_scanning_all_AppData_or_ProgramFiles()
    {
        var plan=ProductScanPlan.Create(Device,new HashSet<Product>{Product.Wps},[]);
        Assert.Contains(@"C:\Users\test\AppData\Local\Kingsoft",plan.Roots);
        Assert.DoesNotContain(@"C:\Users\test\AppData\Local",plan.Roots);
        Assert.DoesNotContain(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),plan.Roots);
        Assert.DoesNotContain(plan.Roots,p=>p.EndsWith("AnyDesk",StringComparison.OrdinalIgnoreCase));
    }
    [Theory]
    [InlineData(@"C:\")][InlineData(@"C:\Users")][InlineData(@"C:\Users\test\AppData")][InlineData(@"C:\Users\test\Downloads")][InlineData(@"C:\Users\test\Documents\WPS")]
    public void Untrusted_registry_cannot_expand_a_direct_scan_to_broad_or_personal_locations(string location)
    {
        var plan=ProductScanPlan.Create(Device,new HashSet<Product>{Product.Wps},[new(Product.Wps,"WPS","1","WPS","key",location,"",false)]);
        Assert.DoesNotContain(location,plan.Roots);Assert.Single(plan.Warnings);
    }
    [Fact]
    public void A_custom_installation_directory_is_retained_for_post_uninstall_cleanup()
    {
        var plan=ProductScanPlan.Create(Device,new HashSet<Product>{Product.AnyDesk},[new(Product.AnyDesk,"AnyDesk","1","AnyDesk","key",@"D:\Tools\RemoteSupport","",true)]);
        Assert.Contains(@"D:\Tools\RemoteSupport",plan.Roots);
    }
    [Fact]
    public void Inferred_uninstaller_subfolder_is_not_mistaken_for_complete_installation_root()
    {
        var app=new InstalledApp(Product.Wps,"WPS","1","WPS","key",@"D:\Tools\Custom\utility",@"D:\Tools\Custom\utility\uninst.exe",true,LocationInferred:true);
        var plan=ProductScanPlan.Create(Device,new HashSet<Product>{Product.Wps},[app]);
        Assert.Contains(app.Location,plan.Roots);Assert.Contains(plan.Warnings,w=>w.Contains("dedujo"));
    }
}
