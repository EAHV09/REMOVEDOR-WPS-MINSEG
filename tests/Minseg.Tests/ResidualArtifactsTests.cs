using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public class ResidualArtifactsTests
{
    private static readonly DeviceInfo Device=new("test","Windows","X64","user","S-1-5-21-1",@"C:\Users\test","user",true,1,[]);
    [Fact]
    public void Targeted_plan_covers_registered_profiles_LocalLow_and_product_data_without_scanning_entire_profiles()
    {
        UserProfile[] profiles=[new(Device.UserSid,Device.ProfilePath),new("S-1-5-21-2",@"D:\Profiles\other")];
        var plan=ProductScanPlan.Create(Device,new HashSet<Product>{Product.Wps,Product.AnyDesk},[],profiles);
        Assert.Contains(@"D:\Profiles\other\AppData\LocalLow\Kingsoft",plan.Roots);
        Assert.Contains(@"D:\Profiles\other\AppData\Roaming\AnyDesk",plan.Roots);
        Assert.Contains(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"WPS"),plan.Roots);
        Assert.Contains(@"D:\Profiles\other\Documents\KingsoftData",plan.PersonalPaths!);
        Assert.Contains(@"D:\Profiles\other\OneDrive\Documentos\WPSDrive",plan.PersonalPaths!);
        Assert.Contains(@"D:\Profiles\other\Desktop",plan.ShortcutRoots!);
        Assert.DoesNotContain(@"D:\Profiles\other",plan.Roots);
        Assert.DoesNotContain(@"D:\Profiles\other\AppData\LocalLow",plan.Roots);
        Assert.DoesNotContain(plan.Roots,r=>r.Contains("WPSDrive",StringComparison.OrdinalIgnoreCase));
        Assert.False(ProductScanPlan.IsNarrowRoot(@"D:\Profiles\other\AppData",Device,profiles));
    }
    [Theory]
    [InlineData(@"C:\ProgramData\WPS\logs\app.log",@"C:\ProgramData\WPS",true)]
    [InlineData(@"C:\ProgramData\Kingsoft\office6\config.ini",@"C:\ProgramData\Kingsoft",true)]
    [InlineData(@"C:\ProgramData\Kingsoft\OtherProduct\config.ini",@"C:\ProgramData\Kingsoft",false)]
    [InlineData(@"C:\ProgramData\Kingsoft\config.ini",@"C:\ProgramData\Kingsoft",false)]
    [InlineData(@"C:\ProgramData\WPS\report.docx",@"C:\ProgramData\WPS",false)]
    [InlineData(@"C:\ProgramData\WPS\run.exe",@"C:\ProgramData\WPS",false)]
    [InlineData(@"C:\ProgramData\WPS-other\app.log",@"C:\ProgramData\WPS",false)]
    [InlineData(@"C:\Users\test\Documents\WPS\app.log",@"C:\Users\test\Documents\WPS",false)]
    public void Technical_cleanup_is_limited_to_known_product_paths_and_non_document_types(string path,string root,bool expected)
        =>Assert.Equal(expected,ResidualArtifacts.TechnicalFile(path,root,Product.Wps));
    [Theory]
    [InlineData(@"Software\Microsoft",false)]
    [InlineData(@"Software\Classes\CLSID",false)]
    [InlineData(@"Software\Classes\CLSID\{DFBCEAD1-EC62-463C-B530-002C00D41C21}",true)]
    [InlineData(@"Software\Classes\CLSID\{DFBCEAD1-EC62-463C-B530-002C00D41C21}\InprocServer32",false)]
    [InlineData(@"Software\Kingsoft\OtherProduct",false)]
    [InlineData(@"Software\Kingsoft\Office6",true)]
    public void Registry_cleanup_cannot_select_broad_or_unrelated_branches(string path,bool expected)
        =>Assert.Equal(expected,RegistryResidues.Allowed(Product.Wps,path));
    [Fact]
    public void Run_cleanup_must_select_an_exact_Run_or_RunOnce_key()
    {
        Assert.True(RegistryResidues.AllowedRun(@"Software\Microsoft\Windows\CurrentVersion\Run"));
        Assert.False(RegistryResidues.AllowedRun(@"Software\Microsoft\Windows\CurrentVersion"));
        Assert.False(RegistryResidues.AllowedRun(@"Software\Microsoft\Windows\CurrentVersion\Run\Other"));
    }
    [Fact]
    public void Shared_Kingsoft_root_does_not_authorize_other_products_directories()
    {
        Assert.True(ResidualArtifacts.TechnicalSubtree(@"C:\ProgramData\Kingsoft\Office6\cache",@"C:\ProgramData\Kingsoft",Product.Wps));
        Assert.False(ResidualArtifacts.TechnicalSubtree(@"C:\ProgramData\Kingsoft\OtherProduct\cache",@"C:\ProgramData\Kingsoft",Product.Wps));
    }
    [Fact]
    public void Own_profile_cleanup_is_not_deferred_just_because_it_contains_directories_or_registry()
    {
        var directory=new Finding(Product.Wps,FindingKind.Directory,"WPS",@"C:\Users\test\AppData\Local\WPS",Trust.Confirmed,"");
        var userKey=new Finding(Product.Wps,FindingKind.Registry,"Office",@"User|S-1-5-21-1|Software\Kingsoft\Office",Trust.Confirmed,"");
        Assert.False(RemovalLaunch.RequiresAdministrator(directory,Device));
        Assert.False(RemovalLaunch.RequiresAdministrator(userKey,Device));
        Assert.True(RemovalLaunch.RequiresAdministrator(userKey with{Location=@"User|S-1-5-21-2|Software\Kingsoft\Office"},Device));
        Assert.True(RemovalLaunch.RequiresAdministrator(directory with{Location=@"C:\ProgramData\WPS"},Device));
    }
    [Fact]
    public void Classes_hive_authorizes_only_exact_CLSID_branches()
    {
        Assert.True(RegistryResidues.AllowedUserClass(@"CLSID\{DFBCEAD1-EC62-463C-B530-002C00D41C21}"));
        Assert.False(RegistryResidues.AllowedUserClass("CLSID"));
        Assert.False(RegistryResidues.AllowedUserClass(@"CLSID\{DFBCEAD1-EC62-463C-B530-002C00D41C21}\Other"));
    }
    [Fact]
    public void Registry_autostarts_are_visible_as_persistence_even_when_their_destination_is_ambiguous()
    {
        var run=new Finding(Product.AnyDesk,FindingKind.Registry,"AnyDesk",@"User|S-1-5-21-2|Software\Microsoft\Windows\CurrentVersion\Run|AnyDesk",Trust.Review,"");
        Assert.True(PersistenceReport.IsPersistence(run));
        Assert.False(PersistenceReport.IsPersistence(run with{Location=@"User|S-1-5-21-2|Software\AnyDesk"}));
    }
    [Fact]
    public void Empty_directory_cleanup_never_removes_children_or_a_different_root()
    {
        var parent=Path.Combine(Path.GetTempPath(),"minseg-test-"+Guid.NewGuid().ToString("N"));
        var root=Path.Combine(parent,"WPS");Directory.CreateDirectory(root);
        var file=Path.Combine(root,"sentinel.txt");File.WriteAllText(file,"keep");
        try
        {
            Assert.False(SafeFileCleaner.DeleteEmptyDirectory(root,root));Assert.Equal("keep",File.ReadAllText(file));
            Assert.ThrowsAny<IOException>(()=>SafeFileCleaner.DeleteEmptyDirectory(parent,root));
            File.Delete(file);Assert.True(SafeFileCleaner.DeleteEmptyDirectory(root,root));Assert.False(Directory.Exists(root));
        }
        finally{if(File.Exists(file))File.Delete(file);if(Directory.Exists(root))Directory.Delete(root);if(Directory.Exists(parent))Directory.Delete(parent);}
    }
}
