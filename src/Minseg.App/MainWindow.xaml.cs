using Microsoft.Win32;
using Minseg.Core;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
namespace Minseg.App;

public partial class MainWindow:Window
{
    private readonly MainViewModel model=new();
    private SecureWorkspace? workspace;
    private CancellationTokenSource? scanCancellation;
    private bool removalWorker;
    private bool workerVerified;
    private bool officeSettingsOpened;
    public MainWindow()
    {
        InitializeComponent();DataContext=model;Activated+=CheckOfficeAfterSettings;UpdateThemeButton();
        MinWidth=Math.Min(MinWidth,SystemParameters.WorkArea.Width-20);
        MinHeight=Math.Min(MinHeight,SystemParameters.WorkArea.Height-20);
        Width=Math.Min(1160,SystemParameters.WorkArea.Width-24);
        Height=Math.Min(680,SystemParameters.WorkArea.Height-24);
    }
    private async void WindowLoaded(object sender,RoutedEventArgs e)
    {
        await Run("Leyendo el equipo…",async()=>
        {
            model.SetDevice(await Task.Run(DeviceInventory.Read));
            model.SetInventory(await Task.Run(()=>InstallationScan.Read(model.Device!)));
            model.Status="Pulsa Escanear equipo para buscar restos y persistencia.";
        });
        var requested=RemovalLaunch.Parse(Environment.GetCommandLineArgs().Skip(1).ToArray());
        if(requested.SequenceEqual(new[]{Product.Wps})&&model.Device?.Administrator==true)
        {removalWorker=true;await Uninstall(requested.ToHashSet());Application.Current.Shutdown(workerVerified?0:2);}
    }
    private async Task RefreshDetection()
    {
        if(model.Device==null)return;
        model.Status="Revisando instalaciones e inicio automático…";
        scanCancellation=new CancellationTokenSource();model.CanCancel=true;model.Notify(nameof(model.CanCancel));
        try
        {
            model.SetInventory(await Task.Run(()=>InstallationScan.Read(model.Device)));
            var products=new HashSet<Product>{Product.Wps};
            var plan=ProductScanPlan.Create(model.Device,products,model.Inventory?.Installed??[]);
            model.SetPersistence(await Task.Run(()=>PersistenceScanner.Read(model.Device,model.Scan,scanCancellation.Token,products,plan.Roots)));
            model.Status="Comprobando Microsoft Office…";
            model.SetOffice(await Task.Run(()=>OfficeRecovery.Read(model.Device)));
        }
        finally{scanCancellation.Dispose();scanCancellation=null;model.CanCancel=false;model.Notify(nameof(model.CanCancel));}
    }
    private async Task Run(string message,Func<Task> action,bool inlineResult=false,Action<string>? errorFeedback=null)
    {
        if(model.Busy)return;model.Busy=true;model.Status=message;
        try{await action();model.Status="Listo. Revisa los resultados y los pendientes.";}
        catch(OperationCanceledException){model.Status="Escaneo cancelado. Revisa el informe de las acciones realizadas.";if(errorFeedback!=null)errorFeedback(model.Status);else if(inlineResult)model.RemovalResult=model.Status;}
        catch(Exception ex){model.Status="No se completó: "+ErrorDetails.Message(ex);model.Diagnostics.Add(ErrorDetails.Diagnostic(ex,message));if(errorFeedback!=null)errorFeedback(model.Status);else if(inlineResult)model.RemovalResult=model.Status;else Dialogs.Error(this,ex,message);}
        finally{model.Busy=false;model.CanCancel=false;model.Notify(null);if(workspace!=null)model.SetEntries(workspace.Entries);}
    }
    private SecureWorkspace Workspace()=>workspace??=new SecureWorkspace();
    private IProgress<string> Progress()=>new Progress<string>(text=>model.Status=text);
    private static ProductScanPlan CreateWpsPlan(DeviceInfo device)
    {
        var warnings=new List<string>();
        var profiles=UserProfiles.Read(device,warnings);
        var installed=InstalledPrograms.ReadAll(device,profiles,warnings);
        var plan=ProductScanPlan.Create(device,new HashSet<Product>{Product.Wps},installed,profiles);
        return plan with{Warnings=plan.Warnings.Concat(warnings).Distinct().ToArray()};
    }
    private async Task Scan()
    {
        if(model.Device==null)return;
        await Run("Buscando WPS…",async()=>
        {
            scanCancellation=new CancellationTokenSource();model.CanCancel=true;model.Notify(nameof(model.CanCancel));
            try
            {
                var result=await new ScanEngine().ScanProductAsync(model.Device,new HashSet<Product>{Product.Wps},
                    await Task.Run(()=>CreateWpsPlan(model.Device)),Progress(),scanCancellation.Token,model.Scan);
                model.SetScanAndInventory(result);
            }
            finally{scanCancellation.Dispose();scanCancellation=null;}
        });
    }
    private async void QuickScan(object sender,RoutedEventArgs e)=>await Run("Buscando instalaciones…",async()=>
    {
        if(model.Device==null)model.SetDevice(await Task.Run(DeviceInventory.Read));
        await RefreshDetection();
    });
    private async void ScanFiles(object sender,RoutedEventArgs e)=>await Scan();
    private void CancelScan(object sender,RoutedEventArgs e)=>scanCancellation?.Cancel();
    private void ShowReport(){AdvancedOptions.IsExpanded=true;ReportExpander.IsExpanded=true;ReportExpander.BringIntoView();}
    private async void UninstallWps(object sender,RoutedEventArgs e)=>await Uninstall(new HashSet<Product>{Product.Wps});
    private async Task Uninstall(HashSet<Product> selected,bool allowElevation=true,bool restoreOffice=false)
    {
        if(!selected.SetEquals(new[]{Product.Wps}))throw new ArgumentException("Esta edición solo desinstala WPS.");
        if(model.Device==null||model.Busy)return;
        model.RemovalResult="Iniciando desinstalación y limpieza…";
        string? resultMessage=null;bool elevate=false;
        await Run("Buscando la instalación…",async()=>
        {
            var inventory=await Task.Run(()=>InstallationScan.Read(model.Device));model.SetInventory(inventory);
            var apps=inventory.Installed.Where(a=>selected.Contains(a.Product)).ToArray();
            // Handle per-user installations at the current token. The elevated copy only executes machine installers.
            restoreOffice|=selected.Contains(Product.Wps);
            if(allowElevation&&RemovalLaunch.NeedsElevation(model.Device.Administrator,inventory,model.Scan,selected,workspace?.RemovalSession))
            {elevate=true;return;}
            scanCancellation=new CancellationTokenSource();
            var store=Workspace();int first=store.Entries.Count;
            try
            {
                var steps=new SystemRemovalSteps(model.Device,store,Progress(),active=>{model.CanCancel=active;model.Notify(nameof(model.CanCancel));},model.SetScan,model.Scan);
                var result=await new RemovalWorkflow(steps).RunAsync(selected,scanCancellation.Token);
                if(steps.NeedsProfileElevation)result=result with{NeedsElevation=result.NeedsElevation.Concat(selected).ToHashSet()};
                workerVerified=selected.All(result.VerifiedClear);
                model.SetScan(result.Scan);model.SetInventory(result.Inventory);
                resultMessage=string.Join("\n\n",selected.Select(result.Summary));
                var pending=store.Entries.Skip(first).Where(e=>e.Status is "Pendiente" or "Revisar" or "Reinicio pendiente").ToArray();
                if(pending.Length>0)resultMessage+="\n\n"+string.Join("\n",pending.Select(e=>e.Product+": "+e.Detail));
                elevate=allowElevation&&!model.Device.Administrator&&!store.RemovalSession.HasPending(selected)&&result.Blocked.Count==0&&(result.NeedsElevation.Count>0||RemovalLaunch.NeedsElevation(false,result.Inventory,result.Scan,selected,store.RemovalSession));
                if(!elevate&&selected.Contains(Product.Wps)&&restoreOffice&&!result.Inventory.Installed.Any(a=>a.Product==Product.Wps)&&result.Inventory.Complete)
                    resultMessage+="\n\n"+await ApplyOfficeInline();
                model.RemovalResult=resultMessage;
            }
            catch(Exception ex)
            {await RefreshAfterChanges(()=>Task.FromException(ex));throw;}
            finally{scanCancellation.Dispose();scanCancellation=null;model.CanCancel=false;model.Notify(nameof(model.CanCancel));}
        },true);
        if(elevate)
        {
            bool resumed=false;int workerExit=-1;model.Busy=true;model.Status="Continuando en la ventana de administrador…";
            try
            {
                var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
                start.ArgumentList.Add("--remove-machine");start.ArgumentList.Add(RemovalLaunch.Argument(selected));
                using var worker=Process.Start(start)??throw new IOException("Windows no pudo abrir la ventana de administrador.");
                await worker.WaitForExitAsync();workerExit=worker.ExitCode;resumed=true;
            }
            catch(Win32Exception ex)when(ex.NativeErrorCode==1223){model.Status="Permiso de administrador cancelado. Las acciones realizadas están en el informe.";model.RemovalResult=model.Status;}
            catch(Exception ex)when(ex is Win32Exception or IOException){model.RemovalResult="No se pudo continuar como administrador: "+ErrorDetails.Message(ex);}
            finally{model.Busy=false;}
            // Keep the original user's scan history. The elevated process never consumes user-written commands or snapshots.
            if(resumed&&workerExit==0)
            {
                await Run("Actualizando el resultado…",async()=>
                {
                    model.InvalidateScanAfterWorker();await RefreshAfterChanges();
                    model.RemovalResult=string.Join("\n",selected.Select(p=>p.Display()+": desinstalación y limpieza comprobadas por la ventana de administrador en las rutas revisadas."));
                    if(selected.Contains(Product.Wps)&&restoreOffice)model.RemovalResult+="\n\n"+await ApplyOfficeInline(false);
                },true);
            }
            else if(resumed)
            {
                Workspace().RemovalSession.RecordMachineContinuation(selected,workerExit);
                const string note="La ventana de administrador dejó acciones pendientes. Revisa su informe y los respaldos en ProgramData\\MINSEG-Control. No se repetirá la desinstalación automáticamente.";
                await Run("Verificando el resultado…",async()=>{await RefreshAfterChanges();var store=Workspace();foreach(var product in selected)store.Log(product,"Continuar como administrador",product.Display(),"Pendiente",note);},true);
                model.Status=note;model.RemovalResult=note;
                if(selected.Contains(Product.Wps)&&restoreOffice&&model.Inventory?.Complete==true&&!model.Inventory.Installed.Any(a=>a.Product==Product.Wps))
                    await Run("Comprobando Microsoft Office…",async()=>model.RemovalResult+="\n\n"+await ApplyOfficeInline(),true);
            }
            return;
        }
        if(resultMessage!=null&&!removalWorker)model.RemovalResult=resultMessage;
    }
    private void ToggleTheme(object sender,RoutedEventArgs e)
    {AppTheme.Apply(!AppTheme.IsDark);UpdateThemeButton();}
    private void UpdateThemeButton()
    {
        ThemeToggle.Content=AppTheme.IsDark?"Modo claro":"Modo oscuro";
        ActionIcon.SetData(ThemeToggle,(System.Windows.Media.Geometry)FindResource(AppTheme.IsDark?"SunIcon":"ThemeIcon"));
    }
    private async Task<bool> RefreshAfterChanges(Func<Task>? refresh=null)
    {
        try{await (refresh??RefreshDetection)();return true;}
        catch(Exception ex)
        {
            var previous=model.Persistence;
            string note=ex is OperationCanceledException?"Verificación posterior cancelada. Los resultados de desinstalación y limpieza se conservan en el informe.":"Verificación posterior incompleta: "+ErrorDetails.Message(ex);
            model.SetPersistence(new(previous?.CapturedAt??DateTimeOffset.Now,previous?.Findings??[],[note],false,previous?.Coverage??PersistenceReport.Scope,previous?.SelectedProducts));
            model.Diagnostics.Add(note);return false;
        }
    }
    private void OpenAdmin(object sender,RoutedEventArgs e)
    {
        if(workspace?.RemovalSession.HasPending(new[]{Product.Wps})==true)
        {Dialogs.Info(this,"Operación pendiente","Hay un desinstalador o una continuación sin confirmar. Revisa el informe; no se abrirá otra ventana para repetir esa operación.");return;}
        try{Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"});Close();}
        catch(Win32Exception){model.Status="No se abrió como administrador. Puedes seguir usando el análisis.";}
    }
    private async void OfficeDefaults(object sender,RoutedEventArgs e)=>await RunOffice("Revisando Office…",async()=>model.OfficeFeedback=await ApplyOfficeInline());
    private Task RunOffice(string message,Func<Task> action)=>Run(message,action,errorFeedback:text=>model.OfficeFeedback=text);
    private async void RefreshOffice(object sender,RoutedEventArgs e)=>await VerifyOffice();
    private async Task VerifyOffice()
    {
        if(model.Device==null)return;
        await RunOffice("Comprobando tus predeterminados…",async()=>
        {
            model.SetOffice(await Task.Run(()=>OfficeRecovery.Read(model.Device)));
            model.OfficeFeedback=model.Office!.Summary+". Revisa la lista para ver lo que falta.";
        });
    }
    private async void CheckOfficeAfterSettings(object? sender,EventArgs e)
    {
        if(!officeSettingsOpened||model.Busy||model.Device==null)return;
        officeSettingsOpened=false;
        await VerifyOffice();
    }
    private async Task<string> ApplyOfficeInline(bool prepare=true)
    {
        // Office is a separate outcome: a failed check must not turn completed cleanup into a failure.
        try{return await ConfigureOfficeCore(prepare);}
        catch(Exception ex)
        {
            model.Diagnostics.Add(ErrorDetails.Diagnostic(ex,"Configurar Office"));
            model.OfficeFeedback="Microsoft Office: no se pudo completar la comprobación. "+ErrorDetails.Message(ex);
            return model.OfficeFeedback;
        }
    }
    private async Task<string> ConfigureOfficeCore(bool prepare)
    {
        if(model.Device==null)return "Microsoft Office: no se pudo comprobar el equipo.";
        model.SetOffice(await Task.Run(()=>OfficeRecovery.Read(model.Device)));
        var plan=model.Office!;
        if(!plan.DetectionComplete||plan.Associations.Count==0)return "Microsoft Office: "+OfficeRecovery.Explain(plan);
        if(!prepare&&plan.DomainJoined)return OfficeAutomation.WorkerFeedback(plan,await Task.Run(()=>OfficePolicy.PreparedMatches(plan)));
        if(!plan.DomainJoined&&plan.CanVerifyUser&&plan.Matched==plan.Associations.Count)return plan.Summary;
        if(OfficeRecovery.RequiresUserChoice(plan))
        {
            if(removalWorker)return OfficeRecovery.PolicyExplanation(plan.PolicyState);
            return plan.Summary+". "+OpenOfficeSettings(plan.Applications.FirstOrDefault(a=>a.Pending>0));
        }
        if(plan.PolicyState=="Unknown")return "Microsoft Office: "+OfficeRecovery.Explain(plan);
        if(!model.Device.Administrator)
        {
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
            start.ArgumentList.Add("--prepare-office");
            try
            {
                using var worker=Process.Start(start)??throw new IOException("Windows no pudo preparar Office como administrador.");
                await worker.WaitForExitAsync();
                model.SetOffice(await Task.Run(()=>OfficeRecovery.Read(model.Device)));
                return worker.ExitCode switch
                {
                    0=>"Office preparado para el próximo inicio de sesión. "+model.Office!.Summary,
                    10=>"XML de esta PC preparado en "+OfficePolicy.PreparedPath+". "+OfficeRecovery.PolicyExplanation(model.Office!.PolicyState),
                    _=>"Office no se pudo preparar. Revisa el informe de administrador en ProgramData\\MINSEG-Control. "+OfficeRecovery.Explain(model.Office!)
                };
            }
            catch(Win32Exception ex)when(ex.NativeErrorCode==1223){return "Windows no recibió permiso de administrador. Office sigue pendiente.";}
        }
        var result=await Task.Run(()=>OfficePolicy.Apply(model.Device,plan,Workspace()));
        model.SetOffice(await Task.Run(()=>OfficeRecovery.Read(model.Device)));
        return "Microsoft Office: "+result;
    }
    private void ConfigureOfficeApp(object sender,RoutedEventArgs e)
    {
        if(sender is FrameworkElement{DataContext:OfficeAppChoice choice})model.OfficeFeedback=OpenOfficeSettings(choice);
    }
    private string OpenOfficeSettings(OfficeAppChoice? choice)
    {
        if(model.Office?.CanVerifyUser!=true)return "Abre la herramienta con el usuario conectado para configurar sus aplicaciones.";
        try
        {
            Process.Start(new ProcessStartInfo(OfficeRecovery.SettingsUri(choice?.RegisteredApplication)){UseShellExecute=true});
            officeSettingsOpened=true;
            return "Se abrió Predeterminados de Windows. "+(choice==null?"Elige las aplicaciones de Office.":choice.Pending==0?$"Revisa la configuración de {choice.Application}.":$"Configura {choice.Application} para sus formatos pendientes: {choice.PendingFormats}.")+" Al volver, comprobaré el resultado. Esto no cambia tus documentos.";
        }
        catch(Exception ex)when(ex is Win32Exception or IOException or InvalidOperationException)
        {return "No se pudo abrir Predeterminados de Windows. "+ErrorDetails.Message(ex);}
    }
    private void ExportOffice(object sender,RoutedEventArgs e)
    {
        if(model.Office?.Associations.Count is not >0){Dialogs.Info(this,"Microsoft Office","No hay formatos comprobados para guardar.");return;}
        var dialog=new SaveFileDialog{Filter="Asociaciones Windows|*.xml",FileName="Microsoft-Office-predeterminados.xml"};
        if(dialog.ShowDialog(this)!=true)return;
        try{OfficeRecovery.Export(model.Office).Save(dialog.FileName);model.Status="XML guardado para TI. Esto no cambia los predeterminados actuales.";}
        catch(Exception ex){Dialogs.Error(this,ex,"Guardar asociaciones de Office");}
    }
    private void OpenDefaults(object sender,RoutedEventArgs e)
    {
        model.OfficeFeedback=OpenOfficeSettings(null);
    }
    private async void RemoveOffice(object sender,RoutedEventArgs e)
    {
        if(!Dialogs.Confirm(this,"Política de Office","Se desactivará solo la política de Office creada por esta herramienta. Las elecciones actuales se conservan. ¿Continuar?"))return;
        await Run("Desactivando política de Office…",async()=>{var store=Workspace();await Task.Run(()=>OfficePolicy.Remove(store));if(model.Device!=null)model.SetOffice(await Task.Run(()=>OfficeRecovery.Read(model.Device)));});
    }
    private void ExportReport(object sender,RoutedEventArgs e)
    {
        var dialog=new SaveFileDialog{Filter="Informe JSON|*.json",FileName="MINSEG-"+(model.Device?.Computer??"equipo")+"-"+DateTime.Now.ToString("yyyyMMdd-HHmm")+".json"};
        if(dialog.ShowDialog(this)!=true)return;
        try
        {
            var scan=model.Scan;
            var report=new{Tool="REMOVEDOR DEL WPS MINSEG",Version=typeof(MainWindow).Assembly.GetName().Version?.ToString(3),Date=DateTimeOffset.Now,Device=model.Device,Department=model.Department,DepartmentSource="Entrada manual",
                InstalledPrograms=model.Inventory?.Installed.Select(a=>new{Product=a.Product.Display(),a.Name,a.Version,a.Publisher,a.Location,a.MachineScope}),InventoryWarnings=model.Inventory?.Warnings,Errors=model.Diagnostics,
                Scan=scan==null?null:new{scan.CapturedAt,scan.Complete,scan.Warnings,scan.Scope,scan.SelectedProducts,
                    Installed=scan.Installed.Select(a=>new{Product=a.Product.Display(),a.Name,a.Version,a.Publisher,a.Location,a.MachineScope}),
                    Findings=scan.Findings.Select(f=>new{Product=f.Product.Display(),Kind=f.Kind.ToString(),f.Name,f.Location,Trust=f.Trust.ToString(),f.Detail,Signer=f.Identity?.Signer,Hash=f.ContentHash??f.Identity?.Sha256})},
                Persistence=model.Persistence==null?null:new{model.Persistence.CapturedAt,model.Persistence.Complete,model.Persistence.Warnings,Scope=model.Persistence.Coverage,model.Persistence.SelectedProducts,Findings=model.Persistence.Findings.Select(f=>new{Product=f.Product.Display(),f.Kind,f.Name,f.Location,f.Trust,f.Detail})},
                Office=model.Office,Policy=model.PolicySummary,PolicyDetail=model.PolicyDetail,Actions=model.Entries};
            File.WriteAllText(dialog.FileName,JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true}),Encoding.UTF8);
            model.Status="Informe guardado. Contiene datos del equipo: compártelo solo con personal autorizado.";
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException){Dialogs.Error(this,ex,"Guardar informe");}
    }
    private void OpenBackups(object sender,RoutedEventArgs e)
    {
        if(workspace==null){Dialogs.Info(this,"Respaldos","Todavía no se crearon respaldos.");return;}
        Process.Start(new ProcessStartInfo(workspace.SessionDirectory){UseShellExecute=true});
    }
    private void ShowAbout(object sender,RoutedEventArgs e)
    {
        var tabs=new TabControl();
        tabs.Items.Add(new TabItem{Header="Ayuda",Content=ReadOnlyText($"REMOVEDOR DEL WPS MINSEG {typeof(MainWindow).Assembly.GetName().Version?.ToString(3)}\n\nEscanear equipo revisa WPS, sus restos y persistencia. Desinstalar WPS inicia la desinstalación, limpia los elementos comprobados y vuelve a revisar. Guarda antes los documentos abiertos. Windows puede pedir permisos y el fabricante puede mostrar su propio asistente.\n\nLas opciones avanzadas contienen Office, las rutas encontradas, el informe y los respaldos. El modo negro y claro se cambia con el botón superior.\n\nEsta edición se centra en WPS. Conserva documentos, archivos de nube y elementos dudosos. No cierra Explorer ni otros programas. Al abrir solo consulta información.\n\nUn único EXE para Windows x64. Registros y respaldos en MINSEG-Control, dentro de ProgramData o AppData local. Office automático requiere una política compatible de dominio y un nuevo inicio de sesión; preparar no significa aplicado.\n\nCódigo Apache 2.0; logos y marcas conservan sus derechos. Compilación sin firma digital institucional.")});
        using(var guide=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.App.Help.Guia")!)
        using(var reader=new StreamReader(guide))tabs.Items.Add(new TabItem{Header="Cómo usarlo",Content=ReadOnlyText(reader.ReadToEnd())});
        using(var guide=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.App.Help.Office")!)
        using(var reader=new StreamReader(guide))tabs.Items.Add(new TabItem{Header="Office para TI",Content=ReadOnlyText(reader.ReadToEnd())});
        foreach(var name in Assembly.GetExecutingAssembly().GetManifestResourceNames().Where(n=>n.Contains(".Licenses.")))
        {using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream(name)!;using var reader=new StreamReader(stream);tabs.Items.Add(new TabItem{Header=name.Split(".Licenses.")[1],Content=ReadOnlyText(reader.ReadToEnd())});}
        new Window{Title="Licencia y ayuda",Owner=this,Width=820,Height=620,Content=tabs,WindowStartupLocation=WindowStartupLocation.CenterOwner}.ShowDialog();
    }
    private static TextBox ReadOnlyText(string text)=>new(){Text=text,IsReadOnly=true,TextWrapping=TextWrapping.Wrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,Margin=new Thickness(15)};
    private void WindowClosing(object? sender,CancelEventArgs e)
    {if(model.Busy){e.Cancel=true;model.Status="Espera a que termine la operación. Puedes cancelar una búsqueda.";return;}workspace?.Dispose();}
}
