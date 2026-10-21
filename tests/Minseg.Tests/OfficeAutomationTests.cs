using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public class OfficeAutomationTests
{
    private static OfficeAssociation Word(string version="16.0.12345.1",string progId="Word.Document.12",string exe=@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
    {
        var identity=new BinaryIdentity(exe,"Microsoft Office","Microsoft Corporation","WINWORD.EXE","Microsoft Corporation",true,"",100);
        return OfficeDiscovery.Registered("Word", ".docx",progId,'"'+exe+"\" /n \"%1\"",identity,version)!;
    }
    [Fact] public void Domain_computer_can_refresh_its_own_Office_configuration_after_an_update()
    {
        Assert.True(OfficePolicy.CanPrepare("Pending"));
    }
    [Fact] public void A_foreign_policy_is_prepared_for_integration_but_never_replaced()
    {
        Assert.False(OfficePolicy.CanSetPolicy("Managed"));
    }
    [Theory]
    [InlineData("14.0.7268.5000","Word.Document.12",@"C:\Office14\WINWORD.EXE")]
    [InlineData("15.0.5571.1000","Word.Document.12",@"C:\Office15\WINWORD.EXE")]
    [InlineData("16.0.10417.20086","Word.Document.12",@"C:\Program Files (x86)\Office16\WINWORD.EXE")]
    [InlineData("16.0.19029.20006","Word.Document.12",@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")]
    public void Uses_each_PC_registered_handler_without_guessing_the_Office_marketing_edition(string version,string progId,string exe)
    {
        var row=Word(version,progId,exe);
        Assert.Equal(version,row.DetectedVersion);Assert.Equal(exe,row.Executable);
        var xml=OfficeAssociationRules.Xml([row]);
        Assert.Equal(progId,xml.Root!.Element("Association")!.Attribute("ProgId")!.Value);
        Assert.Equal("Word",xml.Root.Element("Association")!.Attribute("ApplicationName")!.Value);
    }
    [Fact] public void All_Office_apps_use_only_their_actual_registered_formats()
    {
        var rows=new List<OfficeAssociation>();
        foreach(var pair in OfficeAssociationRules.Apps)
        {
            var exe=@"C:\Office\"+pair.Key;
            var identity=new BinaryIdentity(exe,"Microsoft Office","Microsoft Corporation",pair.Key,"Microsoft Corporation",true,"",100);
            var row=OfficeDiscovery.Registered(pair.Value.Name,pair.Value.Extensions[0],"Registered.Handler.16",'"'+exe+"\" \"%1\"",identity,"16.0.1.2");
            Assert.NotNull(row);rows.Add(row!);
        }
        Assert.Equal(9,OfficeAssociationRules.Xml(rows).Root!.Elements().Count());
        Assert.DoesNotContain(rows,a=>a.Identifier==".pdf"||a.Identifier=="https");
    }
    [Fact] public void Rejects_unsigned_wrong_publisher_and_unrelated_executables()
    {
        var exe=@"C:\Office\WINWORD.EXE";
        var identity=new BinaryIdentity(exe,"Microsoft Office","Microsoft Corporation","WINWORD.EXE","Microsoft Corporation",true,"",100);
        foreach(var bad in new[]{identity with{SignatureValid=false},identity with{Signer="Unknown"},identity with{OriginalName="wps.exe"},identity with{Path=@"C:\Other\WINWORD.EXE"}})
            Assert.Null(OfficeDiscovery.Registered("Word",".docx","Word.Document.12",'"'+exe+'"',bad,"16.0"));
        Assert.Null(OfficeDiscovery.Registered("Word",".pdf","Word.Document.12",'"'+exe+'"',identity,"16.0"));
    }
    [Fact] public void Registry_view_aliases_are_deduplicated_but_conflicting_versions_block_automatic_preparation()
    {
        var warnings=new List<string>();var a=Word();
        Assert.Single(OfficeDiscovery.Select([a,a],warnings,out var complete));Assert.True(complete);
        var selected=OfficeDiscovery.Select([a,Word("15.0",a.ProgId,@"C:\Office15\WINWORD.EXE")],warnings,out complete);
        Assert.Empty(selected);Assert.False(complete);Assert.Contains(warnings,w=>w.Contains(".docx"));
        Assert.Throws<InvalidOperationException>(()=>OfficeAutomation.RequireComplete(new([a],warnings,true,true,"Ready"){DetectionComplete=false}));
    }
    [Theory]
    [InlineData(true,true,null,false,false,false,false,"Ready")]
    [InlineData(true,false,null,false,false,false,false,"Administrator")]
    [InlineData(true,true,"own.xml",false,true,false,false,"Pending")]
    [InlineData(true,true,"prepared.xml",false,false,true,false,"GpoReady")]
    [InlineData(true,true,"prepared.xml",false,false,true,true,"GpoPending")]
    [InlineData(true,true,"company.xml",false,false,false,false,"Managed")]
    [InlineData(true,true,"prepared.xml",true,false,true,true,"Managed")]
    [InlineData(false,true,null,false,false,false,false,"Manual")]
    public void Policy_routing_distinguishes_ownership_domain_and_MDM(bool domain,bool admin,string? path,bool mdm,bool owned,bool prepared,bool verified,string expected)
        =>Assert.Equal(expected,OfficeAutomation.PolicyState(domain,admin,path,mdm,owned,prepared,verified));
    [Fact] public void Machine_configuration_requires_complete_detection_even_when_some_defaults_already_work()
    {
        var good=new OfficePlan([Word()],[],true,false,"Ready");
        OfficeAutomation.RequireComplete(good); // SYSTEM can prepare machine mappings without impersonating a user.
        Assert.Throws<InvalidOperationException>(()=>OfficeAutomation.RequireComplete(good with{DetectionComplete=false}));
        Assert.Throws<InvalidOperationException>(()=>OfficeAutomation.RequireComplete(good with{Associations=[]}));
        Assert.Throws<InvalidOperationException>(()=>OfficeAutomation.RequireComplete(good with{PolicyState="Unknown"}));
    }
    [Fact] public void Headless_mode_rejects_extra_parameters_and_does_not_accept_a_registry_command()
    {
        Assert.Equal(OfficeCommand.Prepare,OfficeAutomation.Parse(["--prepare-office"]));
        Assert.Equal(OfficeCommand.None,OfficeAutomation.Parse([]));
        Assert.Equal(OfficeCommand.Invalid,OfficeAutomation.Parse(["--prepare-office","C:\\evil.xml"]));
        Assert.Equal(OfficeCommand.Invalid,OfficeAutomation.Parse(["--prepare-office=cmd.exe"]));
        Assert.Equal(OfficeCommand.Invalid,OfficeAutomation.Parse(["--remove-machine","wps","--prepare-office"]));
        Assert.Equal(10,new OfficePreparation("file.xml",false,"Preparado, no aplicado").ExitCode);
        Assert.Equal(0,new OfficePreparation("file.xml",true,"Próximo inicio").ExitCode);
    }
    [Fact] public void Prepared_XML_is_atomic_idempotent_and_preserves_unowned_or_changed_content()
    {
        var root=Path.Combine(AppContext.BaseDirectory,"fixtures","MINSEG-OfficeTests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var path=Path.Combine(root,"Office-detectado.xml");
        var original=OfficeAssociationRules.Xml([Word()]).ToString();
        var first=OfficePreparedFile.Save(path,original,null,false);
        Assert.Equal(original,File.ReadAllText(path));Assert.Equal(first,OfficePreparedFile.Save(path,original,first,false));
        Assert.Empty(Directory.GetFiles(root,"*.previous.xml"));
        var revised=OfficeAssociationRules.Xml([Word() with{Identifier=".doc",ProgId="Word.Document.8"}]).ToString();
        Assert.Throws<IOException>(()=>OfficePreparedFile.Save(path,revised,null,false));
        var second=OfficePreparedFile.Save(path,revised,first,false);
        Assert.NotEqual(first,second);Assert.Equal(original,File.ReadAllText(Assert.Single(Directory.GetFiles(root,"*.previous.xml"))));
        File.WriteAllText(path,"Changed externally");
        Assert.Throws<IOException>(()=>OfficePreparedFile.Save(path,original,second,false));
        Assert.Equal("Changed externally",File.ReadAllText(path));
    }
    [Theory]
    [InlineData("Word.Document.12",true)]
    [InlineData("Excel.Sheet.8",true)]
    [InlineData("Outlook.File.msg.15",true)]
    [InlineData("WPS.Docx",false)]
    [InlineData("LibreOffice.WriterDocument.1",false)]
    public void Broken_Office_registration_is_distinguished_from_other_applications(string progId,bool office)
        =>Assert.Equal(office,OfficeDiscovery.IsOfficeProgId(progId));
    [Fact] public void Interrupted_XML_publication_recovers_from_the_protected_pending_hash()
    {
        var root=Path.Combine(AppContext.BaseDirectory,"fixtures",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var path=Path.Combine(root,"Office.xml");var state=new OfficeFileState(null,null);
        var first=OfficePreparedFile.SaveRecoverable(path,"old",state,s=>state=s,false);
        Assert.Throws<IOException>(()=>OfficePreparedFile.SaveRecoverable(path,"new",state,s=>
        {if(s.PendingHash==null)throw new IOException("Simulated registry failure after file publication");state=s;},false));
        Assert.Equal("new",File.ReadAllText(path));Assert.Equal(first,state.CurrentHash);
        Assert.True(state.Accepts(OfficePreparedFile.Hash(path)));
        OfficePreparedFile.SaveRecoverable(path,"new",state,s=>state=s,false);
        Assert.Null(state.PendingHash);Assert.Equal(OfficePreparedFile.Hash(path),state.CurrentHash);
        Assert.Equal("old",File.ReadAllText(Assert.Single(Directory.GetFiles(root,"*.previous.xml"))));
    }
    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void Interrupted_policy_update_keeps_the_actual_pointer_recognizable(int failAt)
    {
        var old=new OfficePolicyFile(@"C:\MINSEG\old.xml","OLD");var next=new OfficePolicyFile(@"C:\MINSEG\new.xml","NEW");
        var state=new OfficePolicyState(old,null);string? pointer=old.Path;int step=0;
        void Interrupt(){if(++step==failAt)throw new IOException("Simulated interruption");}
        Assert.Throws<IOException>(()=>OfficePolicyState.Publish(state,next,pointer,()=>pointer,
            p=>{pointer=p;Interrupt();},s=>{state=s;Interrupt();}));
        Assert.NotNull(state.Find(pointer));Assert.Null(state.Find(@"C:\Foreign\file.xml"));
        OfficePolicyState.Publish(state,next,pointer,()=>pointer,p=>pointer=p,s=>state=s);
        Assert.Equal(next.Path,pointer);Assert.Equal(next,state.Current);Assert.Null(state.Pending);
    }
    [Fact] public void Policy_change_during_preparation_is_preserved()
    {
        var old=new OfficePolicyFile(@"C:\MINSEG\old.xml","OLD");var next=new OfficePolicyFile(@"C:\MINSEG\new.xml","NEW");
        string? pointer=old.Path;bool wrote=false;
        Assert.Throws<IOException>(()=>OfficePolicyState.Publish(new(old,null),next,pointer,()=>pointer,
            p=>{pointer=p;wrote=true;},_=>pointer=@"C:\TI\foreign.xml"));
        Assert.False(wrote);Assert.Equal(@"C:\TI\foreign.xml",pointer);
    }
    [Theory]
    [InlineData("Managed")] [InlineData("GpoPending")] [InlineData("Pending")]
    public void Post_worker_verification_reports_preparation_without_claiming_effective_defaults(string state)
    {
        var plan=new OfficePlan([Word()],[],true,true,state);
        Assert.Contains("XML de esta PC preparado",OfficeAutomation.WorkerFeedback(plan,true));
        Assert.Contains("sigue pendiente",OfficeAutomation.WorkerFeedback(plan,false));
        Assert.Equal(0,plan.Matched);
    }
}
