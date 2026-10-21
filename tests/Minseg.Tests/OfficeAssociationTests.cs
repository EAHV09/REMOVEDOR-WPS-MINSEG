using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class OfficeAssociationTests
{
    [Fact] public void A_matching_ProgId_without_an_opening_target_is_not_reported_ready()
    {
        var a=new OfficeAssociation(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE","Word.Document.12");
        var plan=new OfficePlan([a],[],false,true,"Manual");
        Assert.Equal(0,plan.Matched);
        Assert.True(OfficeRecovery.RequiresUserChoice(plan));
    }
    [Fact] public void Independent_PC_opens_Windows_choice_only_for_unmatched_Office_and_correct_user()
    {
        var a=new OfficeAssociation(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE","WPSOffice.docx.6");
        var plan=new OfficePlan([a],[],false,true,"Manual");
        Assert.True(OfficeRecovery.RequiresUserChoice(plan));
        Assert.False(OfficeRecovery.RequiresUserChoice(plan with{Associations=[a with{CurrentProgId=a.ProgId,CurrentExecutable=a.Executable,CurrentExecutableExists=true}]}));
        Assert.False(OfficeRecovery.RequiresUserChoice(plan with{CanVerifyUser=false}));
        Assert.False(OfficeRecovery.RequiresUserChoice(plan with{PolicyState="Managed"}));
        Assert.False(OfficeRecovery.RequiresUserChoice(plan with{Associations=[]}));
    }
    [Theory]
    [InlineData(".docx","WINWORD.EXE")][InlineData(".xlsx","EXCEL.EXE")][InlineData(".pptx","POWERPNT.EXE")]
    [InlineData("mailto","OUTLOOK.EXE")][InlineData(".accdb","MSACCESS.EXE")][InlineData(".one","ONENOTE.EXE")]
    [InlineData(".pub","MSPUB.EXE")][InlineData(".vsdx","VISIO.EXE")][InlineData(".mpp","WINPROJ.EXE")]
    public void Covers_installed_Office_family(string extension,string exe)=>Assert.True(OfficeAssociationRules.Allowed(extension,exe));
    [Theory][InlineData(".pdf","WINWORD.EXE")][InlineData("https","OUTLOOK.EXE")][InlineData(".docx","EXCEL.EXE")][InlineData(".exe","WINWORD.EXE")]
    public void Does_not_hijack_unrelated_formats(string extension,string exe)=>Assert.False(OfficeAssociationRules.Allowed(extension,exe));
    [Fact] public void Existing_policy_and_unmanaged_PC_are_not_overwritten()
    {
        Assert.Equal("Manual",OfficeAssociationRules.Mode(false,true,null,false));
        Assert.Equal("Managed",OfficeAssociationRules.Mode(true,true,@"C:\Company\defaults.xml",false));
        Assert.Equal("Managed",OfficeAssociationRules.Mode(true,true,null,true));
        Assert.Equal("Administrator",OfficeAssociationRules.Mode(true,false,null,false));
        Assert.Equal("Ready",OfficeAssociationRules.Mode(true,true,null,false));
    }
    [Fact] public void XML_rejects_conflicting_targets_and_unrelated_formats()
    {
        var a=new OfficeAssociation(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE",null);
        Assert.Equal("Word.Document.12",OfficeAssociationRules.Xml([a]).Root!.Element("Association")!.Attribute("ProgId")!.Value);
        Assert.Throws<ArgumentException>(()=>OfficeAssociationRules.Xml([a,a with{ProgId="Word.Other"}]));
        Assert.Throws<ArgumentException>(()=>OfficeAssociationRules.Xml([a with{Identifier=".exe"}]));
    }
    [Fact] public void A_plan_is_not_claimed_applied()
    {
        var plan=new OfficePlan([new(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE","WPS.Docx")],[],true,true,"Ready");
        Assert.Contains("0 de 1",plan.Summary);
    }
}
