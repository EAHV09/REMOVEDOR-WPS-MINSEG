using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class PolicyTests
{
    private static readonly XNamespace Ns="urn:schemas-microsoft-com:sipolicy";
    [Fact]
    public void Deny_policy_allows_unrelated_kernel_and_user_programs()
    {
        var doc=PolicyBuilder.Create(true,1);
        foreach(var value in new[]{"12","131"})
        {
            var scenario=doc.Descendants(Ns+"SigningScenario").Single(n=>(string?)n.Attribute("Value")==value);
            var refs=scenario.Descendants(Ns+"FileRuleRef").Select(n=>(string?)n.Attribute("RuleID")).ToArray();
            Assert.Contains(doc.Descendants(Ns+"Allow"),n=>(string?)n.Attribute("FileName")=="*"&&refs.Contains((string?)n.Attribute("ID")));
        }
        var products=doc.Descendants(Ns+"Deny").Select(n=>(string?)n.Attribute("ProductName")).ToArray();
        Assert.Contains("AnyDesk",products);Assert.Contains("WPS Office",products);
        Assert.DoesNotContain("Microsoft Office",products);
    }
    [Fact]
    public void Audit_and_enforced_modes_are_distinct()
    {
        Assert.Contains(PolicyBuilder.Create(true,1).Descendants(Ns+"Option"),x=>x.Value=="Enabled:Audit Mode");
        Assert.DoesNotContain(PolicyBuilder.Create(false,2).Descendants(Ns+"Option"),x=>x.Value=="Enabled:Audit Mode");
        Assert.Contains(PolicyBuilder.Create(false,2).Descendants(Ns+"Option"),x=>x.Value=="Disabled:Script Enforcement");
    }
    [Fact]
    public void Policy_is_valid_against_Windows_schema()
    {
        var schemas=new XmlSchemaSet();schemas.Add(Ns.NamespaceName,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"schemas","CodeIntegrity","cipolicy.xsd"));
        var errors=new List<string>();PolicyBuilder.Create(true,1).Validate(schemas,(_,e)=>errors.Add(e.Message));Assert.Empty(errors);
    }
    [Fact]
    public void Missing_allow_rules_cannot_pass_validation()
    {
        var doc=PolicyBuilder.Create(false,1);doc.Descendants(Ns+"Allow").Remove();
        Assert.Throws<InvalidOperationException>(()=>PolicyBuilder.Validate(doc));
    }
    [Fact]
    public void Broad_publisher_denies_are_rejected()
    {
        var doc=PolicyBuilder.Create(false,1);
        doc.Root!.Element(Ns+"FileRules")!.Add(new XElement(Ns+"Deny",new XAttribute("ID","ID_DENY_D_X"),new XAttribute("FileName","*")));
        Assert.Throws<InvalidOperationException>(()=>PolicyBuilder.Validate(doc));
    }
    [Fact]
    public void Promotion_keeps_the_exact_audited_rules()
    {
        var audit=PolicyBuilder.Create(true,100);var before=audit.Root!.Element(Ns+"FileRules")!.ToString();
        var enforced=PolicyBuilder.Promote(audit,101);
        Assert.Equal(before,enforced.Root!.Element(Ns+"FileRules")!.ToString());
        Assert.DoesNotContain(enforced.Descendants(Ns+"Option"),x=>x.Value=="Enabled:Audit Mode");
        Assert.Contains(audit.Descendants(Ns+"Option"),x=>x.Value=="Enabled:Audit Mode");
        Assert.NotEqual(audit.Root.Element(Ns+"VersionEx")!.Value,enforced.Root.Element(Ns+"VersionEx")!.Value);
    }
}
