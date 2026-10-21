namespace Minseg.Core;

public sealed record PersistenceReport(DateTimeOffset CapturedAt, IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> Warnings, bool Complete,string Coverage=PersistenceReport.Scope,IReadOnlySet<Product>? SelectedProducts=null)
{
    public static bool IsPersistence(Finding finding)
    {
        if(finding.Kind is FindingKind.Service or FindingKind.Task or FindingKind.Startup)return true;
        if(finding.Kind!=FindingKind.Registry)return false;
        var parts=finding.Location.Split('|',4);
        return parts.Length>=3&&(RegistryResidues.AllowedRun(parts[2])||RegistryResidues.AllowedNamespace(parts[2])||parts[0]=="UserClasses"&&RegistryResidues.AllowedUserClass(parts[2]));
    }
    public string Summary(Product product)
    {
        if(SelectedProducts!=null&&!SelectedProducts.Contains(product))return "Fuera de esta revisión";
        var items=Findings.Where(f=>f.Product==product).ToArray();
        int confirmed=items.Count(f=>f.Trust==Trust.Confirmed), review=items.Count(f=>f.Trust==Trust.Review);
        var result=items.Length==0?(Complete?"Sin persistencia detectada en el alcance revisado":"Escaneo incompleto: no se puede descartar persistencia"):
            $"Persistencia: {confirmed} comprobada(s) · {review} por revisar";
        return items.Length>0&&!Complete?result+" · escaneo incompleto":result;
    }
    public const string Scope="Servicios, tareas programadas, Run/RunOnce (32 y 64 bits) y carpetas de Inicio del equipo y del usuario conectado. No es una búsqueda de malware de todo Windows.";
    public const string FocusedScope="Revisión rápida de servicios, tareas, Run/RunOnce y carpetas de Inicio relacionados por nombre o ruta con los productos seleccionados. No recorre los archivos de instalación ni busca en todos los discos; usa la búsqueda ampliada para otros destinos.";
}

internal static class PersistenceTarget
{
    internal static bool Related(string name,string command,IReadOnlySet<Product> selected,IReadOnlyList<string> roots)
    {
        var hint=Classify(name,command,null);
        if(hint!=null&&selected.Contains(hint.Product))return true;
        var path=PathSafety.ExecutableFromCommand(command);
        return path!=null&&roots.Any(root=>SafetyRules.IsContained(root,path));
    }
    internal static bool ContextDependent(string command)=>System.Text.RegularExpressions.Regex.Matches(command,@"%([^%]+)%").Any(m=>
        !new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432"}.Contains(m.Groups[1].Value,StringComparer.OrdinalIgnoreCase));
    internal static Finding? Classify(string name, string command, BinaryIdentity? identity)
    {
        var confirmed=identity==null||ContextDependent(command)||PathSafety.ExecutableFromCommand(command)==null?null:SafetyRules.Identify(identity);
        string text=name+" "+command+" "+identity?.ProductName+" "+identity?.OriginalName;
        Product? hint=InstalledPrograms.Hint(text);
        if(hint==null&&System.Text.RegularExpressions.Regex.IsMatch(text,@"(?i)(\bWPS\b|\bKingsoft\b)"))hint=Product.Wps;
        if(confirmed==null&&hint==null)return null;
        return new(confirmed??hint!.Value,FindingKind.Binary,name,identity?.Path??command,
            confirmed!=null?Trust.Confirmed:Trust.Review,
            confirmed!=null?"Destino y firma comprobados.":"Coincidencia de nombre o ruta; no autoriza borrar ni cerrar procesos.",identity);
    }
}
internal static class PersistenceLocation
{
    internal static string RunKey(bool machine,string sid,string leaf="Run")=>(machine?"SOFTWARE\\":sid+"\\Software\\")+@"Microsoft\Windows\CurrentVersion\"+leaf;
}
