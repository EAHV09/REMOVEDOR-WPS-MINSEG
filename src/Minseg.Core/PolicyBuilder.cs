using System.Xml.Linq;
using System.Reflection;
using System.Xml;
namespace Minseg.Core;
public static class PolicyBuilder
{
    public const string PolicyId="{2AD8D02D-A472-4E73-AFC0-50B1DB5208A8}";
    public static readonly XNamespace Namespace="urn:schemas-microsoft-com:sipolicy";
    public static readonly string[] KnownProducts=["WPS Office","Kingsoft Office","AnyDesk"];
    public static XDocument Promote(XDocument audited,ulong version)
    {
        Validate(audited);
        if(!audited.Descendants(Namespace+"Option").Any(x=>x.Value=="Enabled:Audit Mode"))throw new InvalidOperationException("La política original no es de auditoría.");
        var copy=new XDocument(audited);
        copy.Descendants(Namespace+"Option").Where(x=>x.Value=="Enabled:Audit Mode").Select(x=>x.Parent!).Remove();
        copy.Root!.Element(Namespace+"VersionEx")!.Value=$"1.{(version>>32)&65535}.{(version>>16)&65535}.{version&65535}";
        Validate(copy);return copy;
    }
    public static XDocument Create(bool audit, ulong version)
    {
        using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.Core.AllowAll.xml")!;
        using var reader=XmlReader.Create(stream,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null});
        var doc=XDocument.Load(reader); var ns=Namespace; var root=doc.Root!;
        root.Element(ns+"PolicyID")!.Value=PolicyId;root.Element(ns+"BasePolicyID")!.Value=PolicyId;
        root.Element(ns+"VersionEx")!.Value=$"1.{(version>>32)&65535}.{(version>>16)&65535}.{version&65535}";
        // Keep Disabled:Script Enforcement: enabling it changes PowerShell/MSHTA behavior for unrelated tools.
        root.Descendants(ns+"Option").Where(n=>n.Value=="Enabled:Audit Mode").Select(n=>n.Parent!).Remove();
        if(audit) root.Element(ns+"Rules")!.Add(new XElement(ns+"Rule",new XElement(ns+"Option","Enabled:Audit Mode")));
        int i=0;
        foreach(var product in KnownProducts)
        {
            string id="ID_DENY_D_MINSEG_"+(++i);
            root.Element(ns+"FileRules")!.Add(new XElement(ns+"Deny",new XAttribute("ID",id),new XAttribute("FriendlyName","MINSEG: "+product),
                new XAttribute("ProductName",product),new XAttribute("MinimumFileVersion","0.0.0.0")));
            root.Descendants(ns+"SigningScenario").Single(n=>(string?)n.Attribute("Value")=="12")
                .Descendants(ns+"FileRulesRef").Single().Add(new XElement(ns+"FileRuleRef",new XAttribute("RuleID",id)));
        }
        root.Descendants(ns+"Setting").Single(n=>(string?)n.Attribute("ValueName")=="Name").Descendants(ns+"String").Single().Value="MINSEG Control - WPS y AnyDesk";
        Validate(doc);return doc;
    }
    public static void Validate(XDocument document)
    {
        var ns=Namespace;
        if(document.Root?.Element(ns+"PolicyID")?.Value.ToUpperInvariant()!=PolicyId) throw new InvalidOperationException("La política no pertenece a esta herramienta.");
        // Microsoft's deny-only policy guidance: preserve explicit allow-all in BOTH signing scenarios.
        foreach(var value in new[]{"12","131"})
        {
            var scenario=document.Descendants(ns+"SigningScenario").Single(n=>(string?)n.Attribute("Value")==value);
            var references=scenario.Descendants(ns+"FileRuleRef").Select(n=>(string?)n.Attribute("RuleID")).ToArray();
            if(!document.Descendants(ns+"Allow").Any(n=>(string?)n.Attribute("FileName")=="*"&&references.Contains((string?)n.Attribute("ID"))))
                throw new InvalidOperationException("Falta la regla que protege los demás programas.");
        }
        foreach(var deny in document.Descendants(ns+"Deny"))
        {
            if(deny.Attribute("Hash")!=null) continue;
            if(!KnownProducts.Contains((string?)deny.Attribute("ProductName"))) throw new InvalidOperationException("Bloqueo demasiado amplio o desconocido.");
        }
        foreach(var denied in document.Descendants(ns+"DeniedSigner"))
        {
            var signer=document.Descendants(ns+"Signer").SingleOrDefault(s=>(string?)s.Attribute("ID")== (string?)denied.Attribute("SignerId"));
            if(signer==null||!signer.Elements(ns+"FileAttribRef").Any())throw new InvalidOperationException("No se permite bloquear un editor completo.");
            foreach(var reference in signer.Elements(ns+"FileAttribRef"))
            {
                var attr=document.Descendants(ns+"FileAttrib").SingleOrDefault(a=>(string?)a.Attribute("ID")== (string?)reference.Attribute("RuleID"));
                if(attr==null||!new[]{"FileName","InternalName","ProductName"}.Any(name=>attr.Attribute(name) is {Value.Length:>0} value&&!value.Value.Contains('*')&&!value.Value.Contains('?')))
                    throw new InvalidOperationException("La regla del editor no limita el archivo o producto.");
            }
        }
    }
}
