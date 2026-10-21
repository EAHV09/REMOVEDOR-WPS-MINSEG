namespace Minseg.Core;

public sealed record ProductScanPlan(IReadOnlyList<string> Roots,IReadOnlyList<string> Warnings,IReadOnlyList<UserProfile>? Profiles=null,IReadOnlyList<string>? PersonalPaths=null,IReadOnlyList<string>? ShortcutRoots=null)
{
    public const string Coverage="Revisión dirigida: carpetas de los productos en los perfiles enumerados, accesos directos y persistencia relacionada. Los perfiles o registros inaccesibles se indican como pendientes. Los documentos y la nube se conservan. Otras rutas requieren búsqueda ampliada.";
    public static ProductScanPlan Create(DeviceInfo device,IReadOnlySet<Product> selected,IEnumerable<InstalledApp> installed,IReadOnlyList<UserProfile>? profiles=null)
    {
        var roots=new List<string>();var warnings=new List<string>();
        profiles??=[new(device.UserSid,device.ProfilePath)];
        var personal=new List<string>();var shortcuts=new List<string>();
        var bases=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}.Concat(profiles.SelectMany(p=>new[]{"AppData\\Local","AppData\\Roaming","AppData\\LocalLow"}.Select(s=>Path.Combine(p.Path,s))));
        foreach(var parent in bases.Where(SafetyRules.IsLocalPath))
        {
            if(selected.Contains(Product.Wps)){roots.Add(Path.Combine(parent,"Kingsoft"));roots.Add(Path.Combine(parent,"WPS Office"));roots.Add(Path.Combine(parent,"WPS"));}
            if(selected.Contains(Product.AnyDesk))roots.Add(Path.Combine(parent,"AnyDesk"));
        }
        shortcuts.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms));
        shortcuts.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
        foreach(var profile in profiles.Where(p=>SafetyRules.IsLocalPath(p.Path)))
        {
            shortcuts.Add(Path.Combine(profile.Path,"Desktop"));
            shortcuts.Add(Path.Combine(profile.Path,@"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
            foreach(var docs in new[]{"Documents","Documentos",@"OneDrive\Documents",@"OneDrive\Documentos"})
                foreach(var folder in new[]{"KingsoftData","WPSDrive"})if(selected.Contains(Product.Wps))personal.Add(Path.Combine(profile.Path,docs,folder));
            shortcuts.Add(Path.Combine(profile.Path,@"OneDrive\Desktop"));shortcuts.Add(Path.Combine(profile.Path,@"OneDrive\Escritorio"));
        }
        foreach(var folder in shortcuts.Where(SafetyRules.IsLocalPath))
        {
            if(selected.Contains(Product.Wps)){roots.Add(Path.Combine(folder,"WPS Office"));roots.Add(Path.Combine(folder,"Kingsoft"));}
            if(selected.Contains(Product.AnyDesk))roots.Add(Path.Combine(folder,"AnyDesk"));
        }
        foreach(var app in installed.Where(a=>selected.Contains(a.Product)))
        {
            if(app.LocationInferred&&app.Location.Length>0)warnings.Add("La carpeta de "+app.Product.Display()+" se dedujo del desinstalador; puede no cubrir toda la instalación. Usa la búsqueda ampliada para revisar otras rutas.");
            if(IsNarrowRoot(app.Location,device,profiles))roots.Add(Path.GetFullPath(app.Location));
            else if(app.Location.Length>0)warnings.Add("La ruta registrada es demasiado amplia o protegida; queda para revisión: "+app.Location);
            else
            {
                try
                {
                    var folder=Path.GetDirectoryName(RegisteredUninstaller.Resolve(app.UninstallCommand))!;
                    if(IsNarrowRoot(folder,device,profiles))roots.Add(folder);
                }
                catch(Exception ex)when(ex is IOException or ArgumentException){ }
                warnings.Add("Falta la carpeta registrada de "+app.Product.Display()+"; la revisión usa sus rutas habituales y la carpeta del desinstalador. Busca también copias en otras rutas.");
            }
        }
        return new(roots.Where(r=>IsNarrowRoot(r,device,profiles)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),warnings,profiles,personal,shortcuts.Where(SafetyRules.IsLocalPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }
    internal static bool IsNarrowRoot(string candidate,DeviceInfo device,IReadOnlyList<UserProfile>? profiles=null)
    {
        if(!SafetyRules.IsLocalPath(candidate)||SafetyRules.IsPersonalData(candidate))return false;
        if(candidate.IndexOfAny(['\"','<','>','|'])>=0||Path.HasExtension(candidate)&&Path.GetExtension(candidate).Equals(".exe",StringComparison.OrdinalIgnoreCase))return false;
        var path=Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        if(path==Path.TrimEndingDirectorySeparator(Path.GetPathRoot(path)!))return false;
        var wide=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}
            .Concat((profiles??[new(device.UserSid,device.ProfilePath)]).SelectMany(p=>new[]{"","AppData",@"AppData\Local",@"AppData\Roaming",@"AppData\LocalLow","Desktop","Downloads"}.Select(s=>Path.Combine(p.Path,s))));
        if(wide.Where(SafetyRules.IsLocalPath).Any(p=>path.Equals(Path.TrimEndingDirectorySeparator(p),StringComparison.OrdinalIgnoreCase)||SafetyRules.IsContained(path,p)))return false;
        var windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return !path.Equals(windows,StringComparison.OrdinalIgnoreCase)&&!SafetyRules.IsContained(windows,path);
    }
}
