namespace Minseg.Core;

public sealed class SystemRemovalSteps(DeviceInfo device,SecureWorkspace workspace,IProgress<string>? progress,
    Action<bool> scanning,Action<ScanResult> report,ScanResult? initialScan=null):IRemovalSteps
{
    private IReadOnlySet<Product> products=new HashSet<Product>();
    private ProductScanPlan? plan;
    private IReadOnlyList<UserProfile> profiles=[];
    private IReadOnlyList<string> profileWarnings=[];
    public bool NeedsProfileElevation{get;private set;}
    public async Task<ScanResult> PrepareAsync(IReadOnlySet<Product> selected,CancellationToken cancellation)
    {
        products=selected;scanning(true);
        try
        {
            progress?.Report("Comprobando la instalación y sus inicios…");
            return await Task.Run(()=>
            {
                cancellation.ThrowIfCancellationRequested();
                var warnings=new List<string>();var allProfiles=UserProfiles.Read(device,warnings);profileWarnings=warnings.ToArray();
                NeedsProfileElevation=!device.Administrator&&(warnings.Count>0||allProfiles.Any(p=>p.Sid!=device.UserSid));
                profiles=device.Administrator?allProfiles:[new(device.UserSid,device.ProfilePath)];
                var apps=InstalledPrograms.ReadAll(device,profiles,warnings);
                var inventory=new ScanResult(DateTimeOffset.Now,[],apps,warnings,warnings.Count==0);
                plan=ProductScanPlan.Create(device,selected,inventory.Installed.Concat(initialScan?.Installed??[]),profiles);
                plan=plan with{Warnings=plan.Warnings.Concat(profileWarnings).Concat(NeedsProfileElevation?["Los otros perfiles se revisarán en la continuación de administrador."]:[]).ToArray()};
                var persistence=PersistenceScanner.Read(device,initialScan,cancellation,selected,plan.Roots);
                var findings=persistence.Findings.Concat(ResidualArtifacts.InstallationEvidence(inventory.Installed,selected)).ToList();
                warnings.AddRange(persistence.Warnings);warnings.AddRange(plan.Warnings);
                ResidualArtifacts.Add(device,plan,selected,findings,warnings,initialScan,cancellation,true);
                return new ScanResult(DateTimeOffset.Now,findings,inventory.Installed,warnings.Distinct().ToArray(),warnings.Count==0,"Preparación dirigida: instalaciones de los perfiles, inicios, accesos y restos técnicos antes de actuar.",selected);
            },cancellation);
        }
        finally{scanning(false);}
    }
    public async Task<ScanResult> ScanAsync(ScanResult? previous,CancellationToken cancellation)
    {
        scanning(true);
        try
        {
            progress?.Report("Buscando restos en las carpetas del producto…");
            var history=WithPriorResidues(previous,initialScan);
            var result=await new ScanEngine().ScanProductAsync(device,products,plan??throw new InvalidOperationException("Falta preparar la búsqueda."),progress,cancellation,history);report(result);return result;
        }
        finally{scanning(false);}
    }
    internal static ScanResult? WithPriorResidues(ScanResult? current,ScanResult? initial)
    {
        if(current==null)return initial;
        if(initial==null)return current;
        // ScanEngine rechecks each residue's path and SHA-256 before carrying it to the fresh result.
        return current with{Findings=current.Findings.Concat(initial.Findings.Where(f=>f.Kind==FindingKind.Residue&&f.Trust==Trust.Confirmed))
            .DistinctBy(f=>(f.Product,f.Kind,f.Location)).ToArray()};
    }
    public async Task<IReadOnlySet<Product>> UninstallAsync(ScanResult before,IReadOnlySet<Product> selected)
    {
        int first=workspace.Entries.Count;
        foreach(var product in selected)workspace.Log(product,"Desinstalar y limpiar",product.Display(),"Inicio","Acción directa iniciada desde el botón. Se comprobarán firma, rutas y restos.");
        // The operator's explicit action replaces the app's extra confirmation. Policy activation retains its own acknowledgements.
        // Machine installers are handled by the UAC continuation, never run with a mismatched token.
        var executableScope=device.Administrator?before:before with{Installed=before.Installed.Where(a=>!a.MachineScope).ToArray()};
        await Task.Run(()=>new UninstallEngine().UninstallAsync(device,executableScope,selected,true,true,workspace,progress));
        return selected.Where(p=>workspace.Entries.Skip(first).Any(e=>e.Product==p.Display()&&e.Action=="Desinstalar"
            &&e.Status is not ("Inicio" or "Desinstalado" or "Ya no está"))).ToHashSet();
    }
    public Task<ScanResult> ReadInventoryAsync()=>Task.Run(()=>{var warnings=device.Administrator?profileWarnings.ToList():new List<string>();var apps=InstalledPrograms.ReadAll(device,profiles,warnings);return new ScanResult(DateTimeOffset.Now,[],apps,warnings,warnings.Count==0);});
    public async Task<CleanupResult> CleanAsync(ScanResult scan,IReadOnlyList<Finding> chosen)
    {
        progress?.Report("Limpiando restos e inicios comprobados…");
        int first=workspace.Entries.Count;
        var needsElevation=new HashSet<Product>();
        foreach(var group in chosen.GroupBy(f=>f.Product))
        {
            var own=device.Administrator?group.ToArray():group.Where(f=>!RemovalLaunch.RequiresAdministrator(f,device)).ToArray();
            if(own.Length<group.Count())
            {needsElevation.Add(group.Key);workspace.Log(group.Key,"Limpiar",group.Key.Display(),"Permiso requerido","Los restos del sistema continuarán como administrador mediante UAC.");}
            if(own.Length==0)continue;
            try{await Task.Run(()=>new UninstallEngine().Clean(device,scan,own,true,true,workspace,progress));}
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
            {workspace.Log(group.Key,"Limpiar",group.Key.Display(),"Pendiente",ErrorDetails.Message(ex));}
        }
        return new(chosen.Select(f=>f.Product).Where(p=>workspace.Entries.Skip(first).Any(e=>e.Product==p.Display()&&e.Status=="Pendiente")).ToHashSet(),needsElevation);
    }
}
