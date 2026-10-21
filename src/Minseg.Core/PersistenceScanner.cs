using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace Minseg.Core;

public static class PersistenceScanner
{
    public static PersistenceReport Read(DeviceInfo device,ScanResult? previous=null,CancellationToken token=default,IReadOnlySet<Product>? selected=null,IReadOnlyList<string>? relatedRoots=null)
    {
        var findings=new List<Finding>();var warnings=new List<string>();
        Add(device,findings,warnings,previous,token,selected,relatedRoots);
        return new(DateTimeOffset.Now,findings.DistinctBy(f=>(f.Kind,f.Location)).ToArray(),warnings,warnings.Count==0,relatedRoots!=null?PersistenceReport.FocusedScope:PersistenceReport.Scope,selected);
    }
    public static void Add(DeviceInfo device,List<Finding> findings,List<string> warnings,ScanResult? previous=null,CancellationToken token=default,IReadOnlySet<Product>? selected=null,IReadOnlyList<string>? relatedRoots=null)
        =>new Reader(device,findings,warnings,previous,token,selected,relatedRoots).Scan();
    internal static Finding Snapshot(Finding finding,string configuration,ScanResult? previous)
    {
        var hash=PersistenceSnapshot.Hash(configuration);
        if(finding.Identity==null)return finding with{Trust=Trust.Review,ContentHash=hash};
        if(!File.Exists(finding.Identity.Path)&&previous?.Findings.Any(f=>f.Trust==Trust.Confirmed&&f.Product==finding.Product&&f.Identity?.Sha256==finding.Identity.Sha256&&f.Kind==finding.Kind&&f.Location==finding.Location&&f.Reference==finding.Reference&&f.ContentHash==hash)!=true)
            return finding with{Trust=Trust.Review,ContentHash=hash,Detail="El destino falta y no coincide con una evidencia comprobada anterior. Se conserva."};
        return finding with{ContentHash=hash};
    }
    private sealed class Reader(DeviceInfo device,List<Finding> findings,List<string> warnings,ScanResult? previous,CancellationToken token,IReadOnlySet<Product>? selected,IReadOnlyList<string>? relatedRoots)
    {
        private readonly Dictionary<string,BinaryIdentity?> cache=new(StringComparer.OrdinalIgnoreCase);
        private readonly Stopwatch watch=Stopwatch.StartNew();
        private int entries;
        private void Warn(string message){if(!warnings.Contains(message))warnings.Add(message);}
        private bool Continue()
        {
            token.ThrowIfCancellationRequested();
            if(++entries<20000&&watch.Elapsed<TimeSpan.FromSeconds(relatedRoots!=null?8:90))return true;
            Warn("Persistencia: límite de tiempo o entradas alcanzado. Resultado parcial.");return false;
        }
        private void Attempt(Action action,string context)
        {
            try{action();}
            catch(Exception ex)when(ex is not OperationCanceledException){Warn("No se pudo revisar: "+context+" ("+ex.GetType().Name+").");}
        }
        private Finding? Resolve(string name,string command)
        {
            if(relatedRoots!=null&&!PersistenceTarget.Related(name,command,selected!,relatedRoots))return null;
            if(PersistenceTarget.ContextDependent(command))
            {Warn("Inicios con variables del usuario o de otra cuenta: requieren revisión en su contexto.");return PersistenceTarget.Classify(name,command,null);}
            var path=PathSafety.ExecutableFromCommand(command);
            if(path==null&&command.Contains(".exe",StringComparison.OrdinalIgnoreCase))Warn("Inicios con rutas ejecutables ambiguas o no locales: requieren revisión manual.");
            BinaryIdentity? identity=null;
            if(path!=null&&!cache.TryGetValue(path,out identity))
            {
                Attempt(()=>
                {
                    PathSafety.RequireNoReparse(path);
                    var version=FileVersionInfo.GetVersionInfo(path);
                    if(PersistenceTarget.Classify(name,command,new(path,version.ProductName??"",version.CompanyName??"",version.OriginalFilename??"","",false,"",0))!=null)
                        identity=new BinaryInspector().Read(path);
                },"destino de inicio "+name);
                if(identity==null&&!File.Exists(path))
                    identity=previous?.Findings.FirstOrDefault(f=>f.Trust==Trust.Confirmed&&f.Identity?.Path.Equals(path,StringComparison.OrdinalIgnoreCase)==true&&f.Kind is FindingKind.Service or FindingKind.Task or FindingKind.Startup)?.Identity;
                cache[path]=identity;
            }
            var finding=PersistenceTarget.Classify(name,command,identity);
            return finding!=null&&(selected==null||selected.Contains(finding.Product))?finding:null;
        }
        public void Scan()
        {
            Attempt(()=>
            {
                using var services=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if(services==null)throw new IOException("Registro de servicios no disponible");
                foreach(var name in services.GetSubKeyNames())
                {
                    if(!Continue())break;
                    Attempt(()=>
                    {
                        using var key=services.OpenSubKey(name);if(key==null)return;
                        string command=key.GetValue("ImagePath",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string??"";
                        var file=Resolve(name,command);if(file==null)return;
                        findings.Add(Snapshot(file with{Kind=FindingKind.Service,Name=name,Location=name,Reference=PathSafety.ExecutableFromCommand(command),Detail=file.Detail+" Servicio registrado; puede estar detenido o deshabilitado."},PersistenceSnapshot.Service(key),previous));
                    },"servicio "+name);
                }
            },"servicios");
            foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
            foreach(var machine in new[]{true,false})
            foreach(var leaf in new[]{"Run","RunOnce"})
            {
                string root=PersistenceLocation.RunKey(machine,device.UserSid,leaf);
                Attempt(()=>
                {
                    using var hive=RegistryKey.OpenBaseKey(machine?RegistryHive.LocalMachine:RegistryHive.Users,view);
                    if(!machine){using var profile=hive.OpenSubKey(device.UserSid);if(profile==null)throw new IOException("Perfil no cargado");}
                    using var run=hive.OpenSubKey(root);if(run==null)return;
                    foreach(var name in run.GetValueNames())
                    {
                        if(!Continue())break;
                        Attempt(()=>
                        {
                            var command=run.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string??"";
                            var file=Resolve(name,command);if(file==null)return;
                            // Cleaner supports only the native Run key. Other vectors remain evidence only.
                            bool cleanable=view==RegistryView.Registry64&&leaf=="Run";
                            string location=(machine?"Machine":"User")+"|"+root+"|"+name;
                            if(!cleanable)location=view+"|"+location;
                            findings.Add(Snapshot(file with{Kind=FindingKind.Startup,Name=name,Location=location,Reference=command,
                                Trust=cleanable?file.Trust:Trust.Review,Detail=file.Detail+(cleanable?" Inicio del registro.":" RunOnce/32 bits: revisión manual; no se limpia automáticamente.")},command,previous));
                        },"inicio "+name);
                    }
                },$"{view} {root}");
            }
            foreach(var folder in new[]{Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),Path.Combine(device.ProfilePath,@"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")})
                Attempt(()=>ReadStartup(folder),"carpeta Inicio");
            Attempt(()=>
            {
                var type=Type.GetTypeFromProgID("Schedule.Service")??throw new IOException("Programador no disponible");
                dynamic scheduler=Activator.CreateInstance(type)!;
                try{scheduler.Connect();ReadFolder(scheduler.GetFolder("\\"),0);}finally{Release(scheduler);}
            },"tareas programadas");
        }
        private void ReadStartup(string folder)
        {
            if(!Directory.Exists(folder))return;PathSafety.RequireNoReparse(folder);
            foreach(var path in Directory.EnumerateFiles(folder))
            {
                if(!Continue())break;
                Attempt(()=>
                {
                    PathSafety.RequireNoReparse(path);string command='"'+path+'"';
                    if(Path.GetExtension(path).Equals(".lnk",StringComparison.OrdinalIgnoreCase))
                    {
                        dynamic shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
                        object? link=null;
                        try{dynamic shortcut=shell.CreateShortcut(path);link=shortcut;command="\""+(string)shortcut.TargetPath+"\" "+(string)shortcut.Arguments;}
                        finally{Release(link);Release(shell);}
                    }
                    var file=Resolve(Path.GetFileName(path),command);if(file==null)return;
                    findings.Add(file with{Kind=FindingKind.Startup,Name=Path.GetFileName(path),Location=path,Reference=command,Trust=Trust.Review,Detail=file.Detail+" Archivo de Inicio: revisar manualmente; no se elimina automáticamente."});
                },"archivo de Inicio "+Path.GetFileName(path));
            }
        }
        private void ReadFolder(dynamic folder,int depth)
        {
            object? tasks=null,children=null;
            try
            {
                if(!Continue())return;
                if(depth>20){Warn("Tareas: profundidad máxima alcanzada.");return;}
                tasks=folder.GetTasks(1);dynamic collection=tasks;
                for(int i=1;i<=collection.Count;i++)
                {
                    if(!Continue())break;
                    dynamic task=collection.Item(i);object? definition=null,actions=null;
                    try
                    {
                        definition=task.Definition;actions=((dynamic)definition).Actions;dynamic list=actions;
                        for(int a=1;a<=list.Count;a++)
                        {
                            dynamic action=list.Item(a);
                            try
                            {
                                if(action.Type!=0){if(relatedRoots==null||PersistenceTarget.Related((string)task.Name,"",selected!,relatedRoots))Warn("Tareas relacionadas con acciones no ejecutables: requieren revisión adicional.");continue;}
                                string rawPath=(string)action.Path;
                                string path=Environment.ExpandEnvironmentVariables(rawPath).Trim('"');
                                string arguments=(string)action.Arguments;
                                var file=Resolve((string)task.Name,"\""+rawPath.Trim('"')+"\" "+arguments);if(file==null)continue;
                                bool single=list.Count==1;
                                findings.Add(Snapshot(file with{Kind=FindingKind.Task,Name=(string)task.Name,Location=(string)task.Path,
                                    Reference=path,Trust=single?file.Trust:Trust.Review,Detail=file.Detail+(single?" Tarea registrada.":" Tarea con varias acciones: revisión manual.")},(string)task.Xml,previous));
                            }
                            finally{Release(action);}
                        }
                    }
                    catch(Exception ex)when(ex is not OperationCanceledException){Warn("Tarea no accesible: "+(string)task.Name);}
                    finally{Release(actions);Release(definition);Release(task);}
                }
                children=folder.GetFolders(0);dynamic subfolders=children;
                for(int i=1;i<=subfolders.Count;i++){if(!Continue())break;ReadFolder(subfolders.Item(i),depth+1);}
            }
            finally{Release(tasks);Release(children);Release(folder);}
        }
        private static void Release(object? value){if(value!=null&&Marshal.IsComObject(value))Marshal.FinalReleaseComObject(value);}
    }
}
