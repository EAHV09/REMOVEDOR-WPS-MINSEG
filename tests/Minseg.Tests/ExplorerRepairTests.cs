using Microsoft.Win32;
using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public sealed class ExplorerRepairTests
{
    private readonly TestTree classes=new(),settings=new(),machine=new();
    private const string WpsId="{AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB}",OfficeId="{CCCCCCCC-1111-2222-3333-DDDDDDDDDDDD}";
    private const string WpsExe=@"C:\Program Files\Kingsoft\WPS Office\office6\wps.exe",WpsDll=@"C:\Program Files\Kingsoft\WPS Office\office6\wpspreview.dll",OfficeExe=@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",OfficeDll=@"C:\Program Files\Microsoft Office\root\Office16\WordPreview.dll";
    private static readonly OfficeAssociation[] Office=[new(".docx","Word.Document.12","Word",OfficeExe,"WPSOffice.docx.6")];
    private static void Set(TestTree hive,string key,string name,string value)=>hive.Values[(key,name)]=value;
    private void Setup()
    {
        Set(classes,@"WPSOffice.docx.6\shell\open\command","","\""+WpsExe+"\" \"%1\"");
        Set(classes,@"CLSID\"+WpsId,"","WPS Writer Preview Handler");Set(classes,@"CLSID\"+WpsId+@"\InprocServer32","",WpsDll);
        Set(machine,@"CLSID\"+OfficeId+@"\InprocServer32","",OfficeDll);
        Set(machine,@"Word.Document.12\shellex\"+ExplorerRepair.Preview,"",OfficeId);
        Set(machine,@"Word.Document.12\shell\open\command","","\""+OfficeExe+"\" /n \"%1\"");
    }
    private IReadOnlyList<ExplorerEdit> Plan(bool trustOffice=true)=>ExplorerRepair.Plan(classes,settings,machine,p=>p==WpsExe||p==WpsDll,p=>trustOffice&&(p==OfficeExe||p==OfficeDll),Office,()=>true);
    [Theory][InlineData(".pdf")][InlineData(".wps")][InlineData(".et")][InlineData(".dps")]
    public void WPS_references_outside_Office_formats_are_removed_without_assigning_them_to_Office(string extension)
    {
        Setup();var key=extension+@"\shellex\"+ExplorerRepair.Preview;Set(classes,key,"",WpsId);
        Set(settings,ExplorerRepair.FileExts+"\\"+extension+@"\OpenWithProgids","WPSOffice.docx.6","");
        var changes=Plan();
        Assert.Contains(changes,c=>c.Key==key&&c.Replacement==null);
        Assert.Contains(changes,c=>c.Key==ExplorerRepair.FileExts+"\\"+extension+@"\OpenWithProgids"&&c.Replacement==null);
    }
    [Fact]
    public void Thousands_of_unrelated_classes_do_not_consume_the_cleanup_budget_before_WPS()
    {
        Setup();Set(classes,@".docx\shellex\"+ExplorerRepair.Preview,"",WpsId);
        for(int i=0;i<6000;i++){Set(classes,"Unrelated."+i,"","keep");Set(classes,@"CLSID\"+Guid.NewGuid().ToString("B")+@"\InprocServer32","",@"C:\Other\library.dll");}
        int calls=0;
        var changes=ExplorerRepair.Plan(classes,settings,machine,p=>p==WpsExe||p==WpsDll,p=>p==OfficeExe||p==OfficeDll,Office,()=>++calls<500);
        Assert.Contains(changes,c=>c.Key==@".docx\shellex\"+ExplorerRepair.Preview&&c.Replacement==OfficeId);
    }
    [Fact]
    public void Broken_WPS_preview_pointer_is_replaced_by_installed_verified_Office_handler()
    {
        Setup();var key=@".docx\shellex\"+ExplorerRepair.Preview;Set(classes,key,"",WpsId);Set(settings,ExplorerRepair.PreviewList,WpsId,"WPS Writer");
        var changes=Plan();
        Assert.Contains(changes,c=>c.Classes&&c.Key==key&&c.Expected==WpsId&&c.Replacement==OfficeId);
        Assert.Contains(changes,c=>!c.Classes&&c.Key==ExplorerRepair.PreviewList&&c.Name==WpsId&&c.Replacement==null);
    }
    [Fact]
    public void WPS_open_override_is_restored_from_Office_but_UserChoice_and_other_apps_are_untouched()
    {
        Setup();var key=@"Word.Document.12\shell\open\command";Set(classes,key,"","\""+WpsExe+"\" \"%1\"");
        Set(settings,ExplorerRepair.FileExts+@"\.docx\OpenWithProgids","WPSOffice.docx.6","");
        Set(settings,ExplorerRepair.FileExts+@"\.docx\OpenWithProgids","Other.Editor","");
        Set(settings,ExplorerRepair.FileExts+@"\.docx\UserChoice","ProgId","WPSOffice.docx.6");
        Set(settings,ExplorerRepair.FileExts+@"\.docx\UserChoice","Hash","keep-hash");
        var changes=Plan();
        Assert.Contains(changes,c=>c.Key==key&&c.Replacement=="\""+OfficeExe+"\" /n \"%1\"");
        Assert.Contains(changes,c=>c.Name=="WPSOffice.docx.6"&&c.Replacement==null);
        Assert.DoesNotContain(changes,c=>c.Key.Contains("UserChoice")||c.Name=="Other.Editor");
    }
    [Fact]
    public void Missing_or_untrusted_Office_dll_is_never_registered_as_preview()
    {
        Setup();var key=@".docx\shellex\"+ExplorerRepair.Preview;Set(classes,key,"",WpsId);
        var changes=Plan(false);
        Assert.Contains(changes,c=>c.Key==key&&c.Replacement==null);
        Assert.DoesNotContain(changes,c=>c.Replacement==OfficeId);
    }
    [Fact]
    public void OpenWith_MRU_keeps_other_apps_and_only_removes_WPS_letter()
    {
        Setup();var key=ExplorerRepair.FileExts+@"\.docx\OpenWithList";
        Set(settings,key,"a","wps.exe");Set(settings,key,"b","WINWORD.EXE");Set(settings,key,"c","other.exe");Set(settings,key,"MRUList","bac");
        var changes=Plan();
        Assert.Contains(changes,c=>c.Key==key&&c.Name=="a"&&c.Replacement==null);
        Assert.Contains(changes,c=>c.Key==key&&c.Name=="MRUList"&&c.Replacement=="bc");
        Assert.DoesNotContain(changes,c=>c.Key==key&&(c.Name=="b"||c.Name=="c"));
    }
    private sealed class TestTree:IExplorerTree
    {
        internal readonly Dictionary<(string Key,string Name),string> Values=new();
        public string? Read(string key,string name="")=>Values.GetValueOrDefault((key,name));
        public string[] Names(string key)=>Values.Keys.Where(p=>p.Key.Equals(key,StringComparison.OrdinalIgnoreCase)).Select(p=>p.Name).ToArray();
        public string[] Children(string key)=>Values.Keys.Select(p=>p.Key).Where(p=>key.Length==0||p.StartsWith(key+"\\",StringComparison.OrdinalIgnoreCase)).Select(p=>(key.Length==0?p:p[(key.Length+1)..]).Split('\\')[0]).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
