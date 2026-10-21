namespace Minseg.Core;

public interface IRemovalSteps
{
    Task<ScanResult> PrepareAsync(IReadOnlySet<Product> selected,CancellationToken cancellation);
    Task<ScanResult> ScanAsync(ScanResult? previous,CancellationToken cancellation);
    Task<IReadOnlySet<Product>> UninstallAsync(ScanResult before,IReadOnlySet<Product> selected);
    Task<ScanResult> ReadInventoryAsync();
    Task<CleanupResult> CleanAsync(ScanResult scan,IReadOnlyList<Finding> chosen);
}

public sealed record CleanupResult(IReadOnlySet<Product> Blocked,IReadOnlySet<Product> NeedsElevation);
public sealed record RemovalResult(ScanResult Scan,ScanResult Inventory,IReadOnlySet<Product> Blocked,IReadOnlySet<Product> NeedsElevation)
{
    public bool VerifiedClear(Product product)=>(Scan.SelectedProducts==null||Scan.SelectedProducts.Contains(product))&&!Blocked.Contains(product)&&!NeedsElevation.Contains(product)&&Scan.Complete&&Inventory.Complete
        &&!Inventory.Installed.Any(a=>a.Product==product)
        &&!Scan.Findings.Any(f=>f.Product==product&&f.Kind!=FindingKind.PersonalData&&f.Kind!=FindingKind.Installation);
    public string Summary(Product product)
    {
        if(VerifiedClear(product))return product.Display()+": sin instalación ni restos detectados en el alcance revisado.";
        var count=Scan.Findings.Count(f=>f.Product==product&&f.Kind!=FindingKind.PersonalData&&f.Kind!=FindingKind.Installation);
        return product.Display()+$": revisión pendiente. {count} elemento(s) por revisar. "+
            (Inventory.Installed.Any(a=>a.Product==product)?"La instalación sigue registrada. ":"")+
            (!Scan.Complete||!Inventory.Complete?"El escaneo fue parcial. ":"")+
            (NeedsElevation.Contains(product)?"Hay restos que necesitan permisos de administrador. ":"")+
            (Blocked.Contains(product)?"Hay acciones sin completar. ":"")+"Consulta el informe.";
    }
}

public sealed class RemovalWorkflow(IRemovalSteps steps)
{
    public async Task<RemovalResult> RunAsync(IReadOnlySet<Product> selected,CancellationToken cancellation)
    {
        if(selected.Count==0||selected.Any(p=>!Enum.IsDefined(p)))throw new ArgumentException("Selecciona WPS o AnyDesk.");
        cancellation.ThrowIfCancellationRequested();
        var before=await steps.PrepareAsync(selected,cancellation);
        cancellation.ThrowIfCancellationRequested();
        var blocked=(await steps.UninstallAsync(before,selected)).ToHashSet();
        var inventory=await steps.ReadInventoryAsync();
        // Do not spend another file traversal when the uninstaller failed or the product is still registered.
        if(!inventory.Complete||selected.All(p=>blocked.Contains(p)||inventory.Installed.Any(a=>a.Product==p)))
            return new(before with{Installed=inventory.Installed,Complete=false,Warnings=before.Warnings.Concat(inventory.Warnings).Append("No se recorrieron archivos: la desinstalación o el registro siguen pendientes.").Distinct().ToArray()},inventory,blocked,new HashSet<Product>());
        var after=await steps.ScanAsync(before,cancellation);
        inventory=await steps.ReadInventoryAsync();
        IReadOnlySet<Product> needsElevation=new HashSet<Product>();
        // A missing registry entry is insufficient if the uninstaller is still running or registry access failed.
        for(int pass=0;pass<3;pass++)
        {
            var chosen=inventory.Complete?after.Findings.Where(f=>selected.Contains(f.Product)&&!blocked.Contains(f.Product)&&!needsElevation.Contains(f.Product)
                &&!inventory.Installed.Any(a=>a.Product==f.Product)&&f.Trust==Trust.Confirmed&&(f.Identity!=null||f.Kind==FindingKind.Directory||KingsoftDataResources.IsFinding(f)||ExplorerResidues.IsFinding(f))
                &&f.Kind is FindingKind.Binary or FindingKind.Residue or FindingKind.Service or FindingKind.Task or FindingKind.Startup or FindingKind.Shortcut or FindingKind.Directory or FindingKind.Registry).ToArray():[];
            if(chosen.Length==0)break;
            cancellation.ThrowIfCancellationRequested();
            var priorLocations=after.Findings.Select(f=>(f.Kind,f.Location,f.Trust,f.ContentHash)).ToHashSet();
            var cleanup=await steps.CleanAsync(after,chosen);blocked.UnionWith(cleanup.Blocked);needsElevation=cleanup.NeedsElevation;
            after=await steps.ScanAsync(after,cancellation);
            inventory=await steps.ReadInventoryAsync();
            if(needsElevation.Count>0)break;
            if(priorLocations.SetEquals(after.Findings.Select(f=>(f.Kind,f.Location,f.Trust,f.ContentHash))))break;
        }
        return new(after,inventory,blocked,needsElevation);
    }
}

public static class RemovalLaunch
{
    public static bool RequiresAdministrator(Finding finding,DeviceInfo? device=null)
    {
        if(finding.Kind is FindingKind.Service or FindingKind.Task)return true;
        if(finding.Kind==FindingKind.Startup)return finding.Location.StartsWith("Machine|",StringComparison.Ordinal);
        if(finding.Kind==FindingKind.Registry)return device==null||!(finding.Location.StartsWith("User|"+device.UserSid+"|",StringComparison.Ordinal)||finding.Location.StartsWith("UserClasses|"+device.UserSid+"|",StringComparison.Ordinal));
        if(device!=null&&finding.Kind is FindingKind.Binary or FindingKind.Residue or FindingKind.Directory or FindingKind.Shortcut)
            return !SafetyRules.IsContained(device.ProfilePath,finding.Location);
        return finding.Kind is FindingKind.Binary or FindingKind.Residue or FindingKind.Directory or FindingKind.Shortcut&&new[]{Environment.SpecialFolder.ProgramFiles,Environment.SpecialFolder.ProgramFilesX86,Environment.SpecialFolder.CommonApplicationData,Environment.SpecialFolder.CommonPrograms,Environment.SpecialFolder.CommonDesktopDirectory}
            .Select(Environment.GetFolderPath).Where(p=>!string.IsNullOrEmpty(p)).Any(p=>finding.Location.StartsWith(p.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase));
    }
    public static bool NeedsElevation(bool administrator,ScanResult inventory,ScanResult? scan,IReadOnlySet<Product> selected,RemovalSession? session=null)
    {
        if(administrator||!inventory.Complete||session?.HasPending(selected)==true)return false;
        var apps=inventory.Installed.Where(a=>selected.Contains(a.Product)).ToArray();
        if(apps.Any(a=>!a.MachineScope))return false;
        return apps.Any(a=>a.MachineScope)||scan?.Findings.Any(f=>selected.Contains(f.Product)&&f.Trust==Trust.Confirmed&&f.Identity!=null
            &&(f.Kind==FindingKind.Service||f.Kind==FindingKind.Startup&&f.Location.StartsWith("Machine|",StringComparison.Ordinal)))==true;
    }
    public static Product[] Parse(IReadOnlyList<string> args)=>args.Count==2&&args[0]=="--remove-machine"?args[1] switch
        {"wps"=>[Product.Wps],"anydesk"=>[Product.AnyDesk],"both"=>[Product.Wps,Product.AnyDesk],_=>[]}:[];
    public static string Argument(IReadOnlySet<Product> selected)
    {
        if(selected.SetEquals(new[]{Product.Wps,Product.AnyDesk}))return "both";
        if(selected.SetEquals(new[]{Product.Wps}))return "wps";
        if(selected.SetEquals(new[]{Product.AnyDesk}))return "anydesk";
        throw new ArgumentException("Selección no válida.");
    }
}
