using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public class OfficeDefaultsGuideTests
{
    private static OfficeAssociation Word()=>new(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE","Word.Document.12")
        {CurrentExecutable=@"C:\Office\WINWORD.EXE",CurrentExecutableExists=true,RegisteredApplication="Word"};

    [Fact] public void Default_requires_both_Office_selection_and_its_present_opening_target()
    {
        var word=Word();
        Assert.True(word.IsDefault);
        Assert.True((word with{CurrentExecutable=@"c:\office\winword.exe"}).IsDefault);
        Assert.False((word with{CurrentExecutableExists=false}).IsDefault);
        Assert.False((word with{CurrentExecutable=null}).IsDefault);
        Assert.False((word with{CurrentExecutable=@"C:\Kingsoft\wps.exe"}).IsDefault);
        Assert.False((word with{CurrentProgId="WPSOffice.docx.6"}).IsDefault);
    }
    [Theory]
    [InlineData("WPSOffice.docx.6",null,"Aún apunta a WPS")]
    [InlineData("Word.Document.12",@"C:\Kingsoft\wps.exe","Aún apunta a WPS")]
    [InlineData("Word.Document.12",null,"Revisar apertura de Word")]
    [InlineData(null,null,"Sin asociación comprobada")]
    [InlineData("Other.Reader",@"C:\Reader\reader.exe","Elegir Word")]
    public void User_sees_the_remaining_problem(string? progId,string? opening,string expected)
        =>Assert.Equal(expected,(Word() with{CurrentProgId=progId,CurrentExecutable=opening,CurrentExecutableExists=false}).Status);

    [Fact] public void Groups_all_detected_Office_apps_and_only_lists_pending_formats()
    {
        var plan=new OfficePlan([Word(),Word() with{Identifier=".doc",CurrentProgId="WPS.Doc"},
            new(".xlsx","Excel.Sheet.12","Excel",@"C:\Office\EXCEL.EXE",null),
            new(".pptx","PowerPoint.Show.12","PowerPoint",@"C:\Office\POWERPNT.EXE",null)],[],false,true,"Manual");
        Assert.Equal(1,plan.Matched);
        Assert.Equal(3,plan.Applications.Count);
        var word=plan.Applications.Single(a=>a.Application=="Word");
        Assert.Equal(".doc",word.PendingFormats);
        Assert.Equal("1 de 2 formatos pendientes",word.Summary);
        Assert.Equal("Word",word.RegisteredApplication);
        Assert.Contains("3 pendientes",plan.Summary);
        Assert.Equal(0,(plan with{CanVerifyUser=false}).Matched);
    }
    [Theory]
    [InlineData(19045,9999,false)]
    [InlineData(22000,1816,false)]
    [InlineData(22000,1817,true)]
    [InlineData(22621,1554,false)]
    [InlineData(22621,1555,true)]
    [InlineData(22631,0,true)]
    [InlineData(26100,0,true)]
    public void Per_app_links_respect_Windows_update_support_and_escape_the_name(int build,int revision,bool supported)
    {
        var uri=OfficeDefaultsGuide.SettingsUri("Office Word & .docx",new Version(10,0,build,revision));
        Assert.Equal(supported?"ms-settings:defaultapps?registeredAppMachine=Office%20Word%20%26%20.docx":"ms-settings:defaultapps",uri);
        Assert.Equal("ms-settings:defaultapps",OfficeDefaultsGuide.SettingsUri(null,new Version(10,0,build,revision)));
    }
    [Fact] public void Readable_report_includes_the_actual_target_and_per_format_result()
    {
        var plan=new OfficePlan([Word() with{CurrentExecutable=@"C:\Kingsoft\wps.exe"}],[],false,true,"Manual");
        var report=OfficeRecovery.Explain(plan);
        Assert.Contains(".docx → Word: Aún apunta a WPS",report);
        Assert.Contains(@"C:\Kingsoft\wps.exe",report);
        Assert.Contains("Comprobar Office",OfficeDefaultsGuide.Steps(false));
        Assert.Contains("Administrar",OfficeDefaultsGuide.Steps(false));
    }
}
