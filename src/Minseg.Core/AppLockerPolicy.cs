using System.Xml.Linq;
using System.Security.Cryptography;
using System.Text;
namespace Minseg.Core;

public static class AppLockerPolicy
{
    public static XDocument Create(bool audit)=>Build(audit);

    private static XDocument Build(bool audit)
    {
        var root=new XElement("AppLockerPolicy",new XAttribute("Version","1"));
        foreach(var type in new[]{"Exe","Msi","Appx"})
        {
            var collection=new XElement("RuleCollection",new XAttribute("Type",type),new XAttribute("EnforcementMode",audit?"AuditOnly":"Enabled"));
            // Microsoft requires an explicit Appx allow collection when enforcing Exe rules.
            // Otherwise Copilot and other unrelated packaged Windows applications can be blocked.
            collection.Add(type=="Appx"?Publisher(type,"*","Allow"):
                new XElement("FilePathRule",Attributes(type,"*","Allow"),new XElement("Conditions",new XElement("FilePathCondition",new XAttribute("Path","*")))));
            // ProductName supports '*' only on its own, never as a prefix/suffix wildcard.
            // Appx remains explicitly allowed: unverified package identities must not be advertised as covered.
            if(type!="Appx")foreach(var name in new[]{"WPS Office","Kingsoft Office","AnyDesk"})
                collection.Add(Publisher(type,name,"Deny"));
            if(type=="Exe")collection.Add(new XElement("RuleCollectionExtensions",
                new XElement("ThresholdExtensions",new XElement("Services",new XAttribute("EnforcementMode","Enabled"))),
                new XElement("RedstoneExtensions")));
            root.Add(collection);
        }
        return new(root);
    }
    private static IEnumerable<XAttribute> Attributes(string type,string product,string action)
    {
        var id=new Guid(SHA256.HashData(Encoding.UTF8.GetBytes("MINSEG-AppLocker-v1|"+type+"|"+product+"|"+action)).AsSpan(0,16));
        return [new("Id",id.ToString("D")),new("Name","MINSEG "+(action=="Allow"?"Permitir otros programas":product)),
            new("Description","MINSEG Control · WPS y AnyDesk"),new("UserOrGroupSid","S-1-1-0"),new("Action",action)];
    }
    private static XElement Publisher(string type,string product,string action)=>new("FilePublisherRule",Attributes(type,product,action),
        new XElement("Conditions",new XElement("FilePublisherCondition",new XAttribute("PublisherName","*"),new XAttribute("ProductName",product),new XAttribute("BinaryName","*"),
            new XElement("BinaryVersionRange",new XAttribute("LowSection","0.0.0.0"),new XAttribute("HighSection","*")))));

    // ASVS 2.2.1: only the exact, bounded rule set produced by this version may be deployed.
    public static void Validate(XDocument policy)
    {
        if(!XNode.DeepEquals(policy,Build(true))&&!XNode.DeepEquals(policy,Build(false)))
            throw new InvalidOperationException("La política AppLocker cambió o contiene reglas no permitidas. No se aplicó.");
    }
    public static XDocument Promote(XDocument policy)
    {
        Validate(policy);
        if(policy.Root!.Elements().Any(c=>(string?)c.Attribute("EnforcementMode")!="AuditOnly"))throw new InvalidOperationException("Primero debe estar en auditoría.");
        var result=new XDocument(policy);foreach(var collection in result.Root!.Elements())collection.SetAttributeValue("EnforcementMode","Enabled");
        Validate(result);return result;
    }
    public static bool Supports(int build,int revision,string edition)
    {
        if(build<17763)return false;
        if(edition.StartsWith("Enterprise",StringComparison.OrdinalIgnoreCase)||edition.StartsWith("Education",StringComparison.OrdinalIgnoreCase)
            ||edition.StartsWith("IoTEnterprise",StringComparison.OrdinalIgnoreCase))return true;
        return build is >=19041 and <=19045&&revision>=2193 || build==22000&&revision>=1219 || build==22621&&revision>=608 || build>22621;
    }
}
