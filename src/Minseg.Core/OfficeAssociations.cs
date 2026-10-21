using System.Xml.Linq;
namespace Minseg.Core;

public sealed record OfficeAssociation(string Identifier,string ProgId,string Application,string Executable,string? CurrentProgId)
{
    public string? CurrentExecutable{get;init;}
    public bool CurrentExecutableExists{get;init;}
    public string? RegisteredApplication{get;init;}
    public string DetectedVersion{get;init;}="No disponible";
    // The ProgID alone is insufficient: a per-user command may still point at the removed WPS binary.
    public bool IsDefault=>string.Equals(ProgId,CurrentProgId,StringComparison.OrdinalIgnoreCase)&&
        CurrentExecutableExists&&string.Equals(Executable,CurrentExecutable,StringComparison.OrdinalIgnoreCase);
    public string Status=>IsDefault?"Listo · "+Application:
        OfficeAssociationRules.IsWpsReference(CurrentProgId,CurrentExecutable)?"Aún apunta a WPS":
        string.IsNullOrWhiteSpace(CurrentProgId)?"Sin asociación comprobada":
        string.Equals(ProgId,CurrentProgId,StringComparison.OrdinalIgnoreCase)?"Revisar apertura de "+Application:"Elegir "+Application;
    public string OpeningTarget=>CurrentExecutable??"Windows no devolvió un programa de apertura";
}
public sealed record OfficeAppChoice(string Application,IReadOnlyList<OfficeAssociation> Formats,bool CanVerify)
{
    public string VersionSummary=>"Versión detectada: "+string.Join(", ",Formats.Select(a=>a.DetectedVersion).Distinct());
    public int Pending=>Formats.Count(a=>!a.IsDefault);
    public string Summary=>!CanVerify?"Comprobar con el usuario conectado":Pending==0?"Todos los formatos comprobados están listos":$"{Pending} de {Formats.Count} formatos pendientes";
    public string PendingFormats=>string.Join(", ",Formats.Where(a=>!a.IsDefault).Select(a=>a.Identifier));
    public string ButtonLabel=>"Configurar "+Application;
    public string? RegisteredApplication=>Formats.Select(a=>a.RegisteredApplication).Distinct(StringComparer.OrdinalIgnoreCase).Count()==1?Formats[0].RegisteredApplication:null;
}
public sealed record OfficePlan(IReadOnlyList<OfficeAssociation> Associations,IReadOnlyList<string> Warnings,bool DomainJoined,bool CanVerifyUser,string PolicyState)
{
    public bool DetectionComplete{get;init;}=true;
    public string DetectionSummary=>Associations.Count==0?"Office no comprobado":
        $"{Applications.Count} aplicaciones · {Associations.Count} formatos registrados"+(DetectionComplete?"":" · detección parcial; no se activa la configuración automática");
    public int Matched=>CanVerifyUser?Associations.Count(a=>a.IsDefault):0;
    public IReadOnlyList<OfficeAppChoice> Applications=>Associations.GroupBy(a=>a.Application).Select(g=>new OfficeAppChoice(g.Key,g.ToArray(),CanVerifyUser)).ToArray();
    public string Summary=>Associations.Count==0?"No se encontraron asociaciones de Office verificadas":
        !CanVerifyUser?"Abre con el usuario conectado para comprobar sus predeterminados":
        Matched==Associations.Count?$"Office: {Matched} formatos listos; destinos de apertura comprobados":$"Office: {Matched} de {Associations.Count} formatos listos · {Associations.Count-Matched} pendientes";
}
internal static class OfficeAssociationRules
{
    internal static bool IsWpsReference(string? progId,string? executable)=>
        System.Text.RegularExpressions.Regex.IsMatch(progId??"",@"^(WPS|WPSOffice|Kingsoft|Kso|ET|WPP)\.",System.Text.RegularExpressions.RegexOptions.IgnoreCase)||
        new[]{"wps.exe","et.exe","wpp.exe","wpspdf.exe"}.Contains(Path.GetFileName(executable??""),StringComparer.OrdinalIgnoreCase);
    internal static readonly Dictionary<string,(string Name,string[] Extensions)> Apps=new(StringComparer.OrdinalIgnoreCase)
    {
        ["WINWORD.EXE"]=("Word",[".doc",".docx",".docm",".dot",".dotx",".dotm",".rtf",".odt"]),
        ["EXCEL.EXE"]=("Excel",[".xls",".xlsx",".xlsm",".xlsb",".xlt",".xltx",".xltm",".csv",".ods"]),
        ["POWERPNT.EXE"]=("PowerPoint",[".ppt",".pptx",".pptm",".pps",".ppsx",".ppsm",".pot",".potx",".potm",".odp"]),
        ["OUTLOOK.EXE"]=("Outlook",[".msg",".eml",".ics",".vcf","mailto"]),
        ["MSACCESS.EXE"]=("Access",[".mdb",".mde",".accdb",".accde",".accdr",".accdt"]),
        ["ONENOTE.EXE"]=("OneNote",[".one",".onepkg",".onetoc2","onenote"]),
        ["MSPUB.EXE"]=("Publisher",[".pub"]),
        ["VISIO.EXE"]=("Visio",[".vsd",".vsdx",".vsdm",".vss",".vssx",".vssm",".vst",".vstx",".vstm"]),
        ["WINPROJ.EXE"]=("Project",[".mpp",".mpt"])
    };
    internal static bool Allowed(string identifier,string exe)=>Apps.TryGetValue(Path.GetFileName(exe),out var app)&&app.Extensions.Contains(identifier,StringComparer.OrdinalIgnoreCase);
    internal static XDocument Xml(IEnumerable<OfficeAssociation> associations)
    {
        var rows=associations.ToArray();
        if(rows.Length==0||rows.GroupBy(a=>a.Identifier,StringComparer.OrdinalIgnoreCase).Any(g=>g.Count()>1))throw new ArgumentException("Lista de asociaciones vacía o ambigua.");
        foreach(var a in rows)
            if(!Allowed(a.Identifier,a.Executable)||!System.Text.RegularExpressions.Regex.IsMatch(a.ProgId,@"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$"))throw new ArgumentException("Asociación de Office no admitida.");
        return new(new XElement("DefaultAssociations",rows.OrderBy(a=>a.Identifier,StringComparer.OrdinalIgnoreCase).Select(a=>new XElement("Association",new XAttribute("Identifier",a.Identifier),new XAttribute("ProgId",a.ProgId),new XAttribute("ApplicationName",a.Application)))));
    }
    internal static string Mode(bool domainJoined,bool admin,string? existingPolicy,bool mdmManaged)
        =>mdmManaged||!string.IsNullOrEmpty(existingPolicy)?"Managed":!domainJoined?"Manual":!admin?"Administrator":"Ready";
}
