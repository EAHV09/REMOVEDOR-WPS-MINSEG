using System.Xml.Linq;
using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public sealed class AppLockerTests
{
    [Theory]
    [InlineData("Exe")]
    [InlineData("Msi")]
    public void EachCollectionAllowsOtherAppsAndDeniesBothProducts(string type)
    {
        var collection=AppLockerPolicy.Create(true).Root!.Elements("RuleCollection").SingleOrDefault(c=>(string?)c.Attribute("Type")==type);
        Assert.NotNull(collection);
        Assert.Contains(collection.Elements(),r=>(string?)r.Attribute("Action")=="Allow"&&(string?)r.Attribute("UserOrGroupSid")=="S-1-1-0");
        var targets=collection.Elements().Where(r=>(string?)r.Attribute("Action")=="Deny").Descendants("FilePublisherCondition").Select(c=>(string?)c.Attribute("ProductName")).ToArray();
        Assert.Contains(targets,p=>p!.Contains("WPS",StringComparison.OrdinalIgnoreCase));
        Assert.Contains(targets,p=>p!.Contains("AnyDesk",StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(targets,p=>p=="*"||p!.Contains("Microsoft"));
        Assert.All(targets,p=>Assert.DoesNotContain('*',p!));
    }
    [Fact]
    public void PackagedWindowsAppsHaveExplicitAllowAndNoUnverifiedDenies()
    {
        var collection=AppLockerPolicy.Create(true).Root!.Elements("RuleCollection").Single(c=>(string?)c.Attribute("Type")=="Appx");
        Assert.Single(collection.Elements("FilePublisherRule"));
        Assert.Equal("Allow",(string?)collection.Element("FilePublisherRule")!.Attribute("Action"));
    }
    [Fact]
    public void ExecutablesLaunchedByServicesAreAlsoCovered()
    {
        var doc=AppLockerPolicy.Create(true);
        Assert.Equal("Enabled",(string?)doc.Descendants("Services").Single().Attribute("EnforcementMode"));
    }
    [Fact]
    public void MissingStoreAllowIsRejectedToProtectCopilotAndNativeApps()
    {
        var doc=AppLockerPolicy.Create(true);
        doc.Root!.Elements("RuleCollection").Where(c=>(string?)c.Attribute("Type")=="Appx").Remove();
        Assert.Throws<InvalidOperationException>(()=>AppLockerPolicy.Validate(doc));
    }
    [Fact]
    public void BroadDenyCannotBeApplied()
    {
        var doc=AppLockerPolicy.Create(true);
        doc.Root!.Add(new XElement("RuleCollection",new XAttribute("Type","Exe"),new XAttribute("EnforcementMode","Enabled"),new XElement("FilePathRule",new XAttribute("Action","Deny"))));
        Assert.Throws<InvalidOperationException>(()=>AppLockerPolicy.Validate(doc));
    }
    [Fact]
    public void PromotionChangesOnlyModesNotAuditedRules()
    {
        var audit=AppLockerPolicy.Create(true);var enforced=AppLockerPolicy.Promote(audit);
        Assert.Equal(3,enforced.Root!.Elements("RuleCollection").Count(c=>(string?)c.Attribute("EnforcementMode")=="Enabled"));
        foreach(var collection in enforced.Root.Elements("RuleCollection"))collection.SetAttributeValue("EnforcementMode","AuditOnly");
        Assert.True(XNode.DeepEquals(audit,enforced));
    }
    [Theory]
    [InlineData(17763,1,"EnterpriseS",true)]
    [InlineData(19045,2193,"Professional",true)]
    [InlineData(19045,2000,"Professional",false)]
    [InlineData(19045,2193,"Core",true)]
    [InlineData(17134,4000,"Enterprise",false)]
    [InlineData(19045,1,"Enterprise",true)]
    public void UnsupportedWindowsDoesNotClaimEnforcement(int build,int revision,string edition,bool expected)
        =>Assert.Equal(expected,AppLockerPolicy.Supports(build,revision,edition));
}
