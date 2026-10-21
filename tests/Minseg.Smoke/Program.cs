using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Minseg.App;
using Minseg.Core;
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try{return Execute(args);}catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
    }
    private static int Execute(string[] args)
    {
        if(args.Length==3&&args[0]=="--check-resource")return CheckResource(args[1],args[2]);
        if(args.Length==2&&args[0]=="--probe")return Probe(args[1]);
        if(args.Length!=1)throw new ArgumentException("Indica una carpeta de salida para las capturas.");
        var output=Path.GetFullPath(args[0]);Directory.CreateDirectory(output);
        // Suppress interactive startup when the render dispatcher pumps; never show a second window or scan the host.
        var app=(App)Activator.CreateInstance(typeof(App),BindingFlags.Instance|BindingFlags.NonPublic,null,[true],null)!;
        app.InitializeComponent();AppTheme.Apply(true);
        var window=new MainWindow();var model=(MainViewModel)window.DataContext;
        var oldTime=DateTimeOffset.Now.AddHours(-1);
        model.SetScan(new(oldTime,[new(Product.Wps,FindingKind.Binary,"old.exe",@"C:\Tools\old.exe",Trust.Review,"")],[],["Carpeta no accesible"],false));
        model.SetPersistence(new(DateTimeOffset.Now,[],[],true));
        if(model.Scan!.Complete||!model.Scan.Warnings.Contains("Carpeta no accesible")||model.Scan.CapturedAt!=oldTime)
            throw new InvalidOperationException("La revisión de persistencia borró el alcance o rejuveneció evidencia de archivos.");
        model.Entries.Add(new(DateTimeOffset.Now,"WPS Office","Desinstalar","WPS","Desinstalado","Resultado de prueba"));
        var refresh=typeof(MainWindow).GetMethod("RefreshAfterChanges",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var completed=((Task<bool>)refresh.Invoke(window,[new Func<Task>(()=>Task.FromException(new OperationCanceledException()))])!).GetAwaiter().GetResult();
        if(completed||model.Persistence?.Complete!=false||model.Entries.Single().Status!="Desinstalado"||!model.Persistence.Warnings.Any(w=>w.Contains("cancelada")))
            throw new InvalidOperationException("Cancelar verificación posterior ocultó una desinstalación ya realizada.");
        model.Entries.Clear();model.Diagnostics.Clear();
        // An Office failure must not overwrite an already completed uninstall's result.
        var runOffice=typeof(MainWindow).GetMethod("RunOffice",BindingFlags.Instance|BindingFlags.NonPublic)!;
        model.RemovalResult="WPS desinstalado; limpieza comprobada.";
        ((Task)runOffice.Invoke(window,["Comprobar Office",new Func<Task>(()=>Task.FromException(new IOException("Office no disponible")))])!).GetAwaiter().GetResult();
        if(model.RemovalResult!="WPS desinstalado; limpieza comprobada."||!model.OfficeFeedback.Contains("Office no disponible"))
            throw new InvalidOperationException("Un fallo de Office ocultó el resultado de desinstalación.");
        model.OfficeFeedback="";model.Diagnostics.Clear();
        model.InvalidateScanAfterWorker();
        if(model.Scan!=null||model.Persistence!=null||model.WpsFindings.Count!=0||model.AnyDeskFindings.Count!=0)
            throw new InvalidOperationException("La continuación UAC dejó hallazgos antiguos en pantalla.");
        var pendingRun=new Finding(Product.Wps,FindingKind.Registry,"WPS",@"User|S-1-5-21-1|Software\Microsoft\Windows\CurrentVersion\Run|WPS",Trust.Review,"Destino ambiguo");
        model.SetScan(new(DateTimeOffset.Now,[pendingRun],[],[],true));model.SetPersistence(new(DateTimeOffset.Now,[],[],true));
        if(model.Persistence==null||!model.Persistence.Findings.Contains(pendingRun)||!model.WpsPersistence.Contains("por revisar"))
            throw new InvalidOperationException("La detección rápida ocultó un inicio del registro pendiente.");
        if(window.Background is not SolidColorBrush canvas || canvas.Color.R>70 || canvas.Color.G>70 || canvas.Color.B>80 ||
           window.Foreground is not SolidColorBrush ink || ink.Color.R<220)
            throw new InvalidOperationException("Contraste real de MainWindow incorrecto: fondo claro o texto oscuro.");
        model.SetInventory(new(DateTimeOffset.Now,[],[],["No se pudo leer el registro"],false));
        model.SetScan(new(DateTimeOffset.Now,[],[],[],true));
        if(InstallationScan.State(model.Inventory,Product.Wps)!=InstallationState.Unknown)
            throw new InvalidOperationException("La búsqueda de archivos ocultó un error de inventario y afirmó que WPS no está instalado.");
        // Synthetic display data; no host mutations, scans, policies or desinstallers are invoked here.
        model.SetDevice(new DeviceInfo("MINSEG-PC-024","Windows 11 Enterprise","X64","MINSEG\\usuario","S-1-0-0",@"C:\Users\usuario","MINSEG\\usuario",false,1,[new("Ethernet","Ethernet","Up","192.0.2.24","02:00:00:00:00:24")]));
        model.Department="Ciberseguridad";
        var version=new BinaryIdentity(@"C:\Program Files\AnyDesk\AnyDesk.exe","AnyDesk","AnyDesk","AnyDesk.exe","AnyDesk Software GmbH",true,new string('A',64),1000);
        model.SetScan(new(DateTimeOffset.Now,[new(Product.AnyDesk,FindingKind.Binary,"AnyDesk.exe",version.Path,Trust.Confirmed,"Ejemplo de un archivo comprobado",version)],
            [new(Product.Wps,"WPS Office","12","Kingsoft","HKLM/example",@"C:\Program Files\WPS Office","",true),new(Product.AnyDesk,"AnyDesk","9","AnyDesk","HKLM/example2",version.Path,"",true)],[],true));
        model.SetInventory(model.Scan!);
        model.SetPersistence(new(DateTimeOffset.Now,[new(Product.AnyDesk,FindingKind.Service,"AnyDesk","AnyDesk",Trust.Confirmed,"Servicio con destino firmado comprobado.",version)],[],true));
        model.SetOffice(new([new(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE","WPS.Docx"){CurrentExecutable=@"C:\Kingsoft\wps.exe",RegisteredApplication="Word"},
            new(".xlsx","Excel.Sheet.12","Excel",@"C:\Office\EXCEL.EXE","Excel.Sheet.12"){CurrentExecutable=@"C:\Office\EXCEL.EXE",CurrentExecutableExists=true,RegisteredApplication="Excel"},
            new(".pptx","PowerPoint.Show.12","PowerPoint",@"C:\Office\POWERPNT.EXE",null){RegisteredApplication="PowerPoint"}],[".doc: varias versiones registradas; se conserva la selección actual."],false,true,"Manual"));
        if(model.OfficeApplications.Count!=3||!model.OfficeSummary.Contains("1 de 3")||model.OfficeApplications.Single(a=>a.Application=="Word").PendingFormats!=".docx")
            throw new InvalidOperationException("La lista Office no refleja las asociaciones pendientes.");
        model.Status="Vista de prueba · datos de ejemplo";
        var root=(FrameworkElement)window.Content;root.DataContext=model;
        root.SetResourceReference(System.Windows.Documents.TextElement.ForegroundProperty,"Ink");
        System.Windows.Documents.TextElement.SetFontFamily(root,window.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(root,window.FontSize);
        // Keep the visual in its actual Window so WPF invalidates DynamicResource bindings when the theme changes.
        var surface=root;root.SetResourceReference(Panel.BackgroundProperty,"Canvas");
        foreach(var pair in new[]{(0,0,"interfaz-inicio.png",1100,780),(0,0,"interfaz-compacta.png",900,550),(1,0,"interfaz-bloqueo.png",1100,650),(2,0,"interfaz-equipo.png",1100,650),(3,0,"interfaz-wps.png",1100,650),(3,1,"interfaz-anydesk.png",1100,650),(3,2,"interfaz-informe.png",1100,650)})
        {
            ((TabControl)window.FindName("Pages")).SelectedIndex=pair.Item1;
            ((TabControl)window.FindName("ToolsPages")).SelectedIndex=pair.Item2;
            Render(surface,pair.Item4,pair.Item5,Path.Combine(output,pair.Item3));
            if(pair.Item1==0)foreach(var name in new[]{"WpsAction","AnyDeskAction","StatusLabel"})
            {
                var element=(FrameworkElement)window.FindName(name);
                var bounds=element.TransformToAncestor(surface).TransformBounds(new Rect(0,0,element.ActualWidth,element.ActualHeight));
                if(bounds.Top<0||bounds.Bottom>pair.Item5||bounds.Left<0||bounds.Right>pair.Item4)throw new InvalidOperationException(name+" queda fuera de la ventana.");
            }
        }
        ((TabControl)window.FindName("Pages")).SelectedIndex=0;
        model.Busy=true;model.Status="Escaneando el equipo…";
        Render(surface,1100,780,Path.Combine(output,"interfaz-escaneando.png"));
        foreach(var text in VisualChildren<TextBlock>((FrameworkElement)window.FindName("WorkArea")))
        {
            DependencyObject? ancestor=text;while(ancestor!=null&&ancestor is not Button)ancestor=VisualTreeHelper.GetParent(ancestor);
            if(ancestor is Button)continue; // Colored buttons intentionally use dark ink on bright fills.
            if(text.Foreground is SolidColorBrush brush&&text.Text.Length>0&&brush.Color.R<120&&brush.Color.G<120&&brush.Color.B<120)
                throw new InvalidOperationException("Texto oscuro durante el escaneo: "+text.Text);
        }
        foreach(var button in VisualChildren<Button>((FrameworkElement)window.FindName("WorkArea")))
            if(button.Content is string&&ActionIcon.GetData(button)==null)throw new InvalidOperationException("Falta icono: "+button.Content);
        model.Busy=false;
        // Exercise the real button in both directions; theme changes must update existing controls.
        var toggle=(Button)window.FindName("ThemeToggle");toggle.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Render(surface,1100,780,Path.Combine(output,"interfaz-clara.png"));
        Render(surface,900,550,Path.Combine(output,"interfaz-clara-compacta.png"));
        if(AppTheme.IsDark||window.Background is not SolidColorBrush light||light.Color.R!=255||window.Foreground is not SolidColorBrush darkInk||darkInk.Color.R>80||toggle.Content?.ToString()!="Modo oscuro")
            throw new InvalidOperationException("El botón no cambió al fondo blanco con texto oscuro.");
        foreach(var text in VisualChildren<TextBlock>((FrameworkElement)window.FindName("WorkArea")))
            if(text.Text.Length>0&&text.Foreground is SolidColorBrush brush&&brush.Color.R>220&&brush.Color.G>220&&brush.Color.B>220)
                throw new InvalidOperationException("Texto blanco ilegible en modo claro: "+text.Text);
        toggle.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Render(surface,1100,780,Path.Combine(output,"interfaz-oscura-restaurada.png"));
        if(!AppTheme.IsDark||window.Background is not SolidColorBrush restored||restored.Color.R>70||toggle.Content?.ToString()!="Modo claro")
            throw new InvalidOperationException("No se recuperó el modo oscuro.");
        // Show the actual Office controls and their expanded diagnostics without opening Windows Settings.
        ((TabControl)window.FindName("Pages")).SelectedIndex=0;
        var officeList=(ItemsControl)window.FindName("OfficeAppsList");
        var formats=(Expander)window.FindName("OfficeFormatsPanel");formats.IsExpanded=true;
        model.Status="Vista de prueba · asociaciones de Office";
        Render(surface,1100,780,Path.Combine(output,"interfaz-office-preparacion.png"));
        var homeScroll=(ScrollViewer)((TabItem)((TabControl)window.FindName("Pages")).Items[0]).Content;
        homeScroll.ScrollToEnd();
        Render(surface,1100,780,Path.Combine(output,"interfaz-office.png"));
        var officeGrid=(DataGrid)window.FindName("OfficeFormatsGrid");
        if(officeGrid.Columns[0].ActualWidth<80||officeGrid.Columns[2].ActualWidth<230||officeGrid.ColumnHeaderHeight!=36)
            throw new InvalidOperationException("La tabla de formatos Office no tiene columnas legibles.");
        if(!((TextBlock)window.FindName("OfficeWarningsLabel")).Text.Contains(".doc: varias versiones"))
            throw new InvalidOperationException("Los formatos excluidos quedaron ocultos en la interfaz.");
        var officeButtons=VisualChildren<Button>(officeList).Where(b=>b.Content is string).ToArray();
        if(officeButtons.Length!=3||!officeButtons.Any(b=>b.Content?.ToString()=="Configurar Word")||officeButtons.Any(b=>ActionIcon.GetData(b)==null))
            throw new InvalidOperationException("Falta un control Office con su icono.");
        model.SetOffice(model.Office! with{Associations=model.Office.Associations.Select(a=>a with{CurrentProgId=a.ProgId,CurrentExecutable=a.Executable,CurrentExecutableExists=true}).ToArray()});
        Render(surface,1100,780,Path.Combine(output,"interfaz-office-listo.png"));
        if(model.Office.Matched!=3||model.OfficeApplications.Any(a=>a.Pending!=0)||model.OfficeDetail.Contains("Falta tu elección"))
            throw new InvalidOperationException("Office conserva pendientes después de comprobar la selección y el destino.");
        formats.IsExpanded=false;
        surface.UpdateLayout();
        homeScroll.ScrollToEnd();
        Render(surface,1100,780,Path.Combine(output,"interfaz-office-resumen.png"));
        toggle.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Render(surface,900,550,Path.Combine(output,"interfaz-office-clara-compacta.png"));
        toggle.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        // Domain workflow prepares every detected Office app together; no per-app Windows Settings steps.
        model.SetOffice(model.Office! with{DomainJoined=true,PolicyState="Administrator",Warnings=[],DetectionComplete=true,
            Associations=model.Office.Associations.Select(a=>a with{DetectedVersion="16.0.19029.20006",CurrentProgId="WPS.Previous",CurrentExecutable=@"C:\Kingsoft\wps.exe"}).ToArray()});
        homeScroll.ScrollToEnd();
        Render(surface,1100,900,Path.Combine(output,"interfaz-office-dominio.png"));
        homeScroll.ScrollToEnd();
        Render(surface,1100,900,Path.Combine(output,"interfaz-office-dominio.png"));
        if(model.OfficeButton!="Preparar Office automático"||model.OfficeManual||!model.OfficeSteps.Contains("próximo inicio de sesión")||
            VisualChildren<Button>(officeList).Any(b=>b.Visibility!=Visibility.Collapsed))
            throw new InvalidOperationException("El flujo de dominio todavía pide configurar cada aplicación.");
        model.SetOffice(model.Office! with{PolicyState="GpoPending"});
        Render(surface,1100,900,Path.Combine(output,"interfaz-office-gpo.png"));
        if(model.Office.Matched!=0||!model.OfficeDetail.Contains("GPO"))throw new InvalidOperationException("Preparar la GPO se confundió con predeterminados aplicados.");
        model.SetOffice(model.Office! with{DetectionComplete=false,Warnings=[".doc: varias instalaciones de Office compiten; configuración automática pendiente."]});
        Render(surface,900,550,Path.Combine(output,"interfaz-office-parcial.png"));
        if(!model.OfficeDetection.Contains("detección parcial"))throw new InvalidOperationException("Falta avisar que la detección fue parcial.");
        // Render the actual error dialog body without showing a window or invoking operations.
        var dialogs=typeof(MainWindow).Assembly.GetType("Minseg.App.Dialogs")!;
        var create=dialogs.GetMethod("Create",BindingFlags.NonPublic|BindingFlags.Static)!;
        var empty=new System.Runtime.InteropServices.COMException("",unchecked((int)0x80070005));
        var tuple=((Window,StackPanel,StackPanel))create.Invoke(null,[window,"No se pudo completar",ErrorDetails.Message(empty)])!;
        var accept=new Button{Content="Aceptar"};ActionIcon.SetData(accept,(Geometry)app.Resources["CheckIcon"]);tuple.Item3.Children.Add(accept);
        var dialogContent=(FrameworkElement)tuple.Item1.Content;tuple.Item1.Content=null;
        System.Windows.Documents.TextElement.SetForeground(dialogContent,tuple.Item1.Foreground);
        System.Windows.Documents.TextElement.SetFontFamily(dialogContent,tuple.Item1.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(dialogContent,tuple.Item1.FontSize);
        Render(new Border{Background=tuple.Item1.Background,Child=dialogContent},580,300,Path.Combine(output,"aviso-corregido.png"));
        AppLockerPolicy.Create(true).Save(Path.Combine(output,"applocker-audit.xml"));
        AppLockerPolicy.Promote(AppLockerPolicy.Create(true)).Save(Path.Combine(output,"applocker-enforce.xml"));
        PolicyBuilder.Create(true,(ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).Save(Path.Combine(output,"policy-test.xml"));
        File.WriteAllText(Path.Combine(output,"samples.json"),"[]");
        using(var resource=typeof(PolicyBuilder).Assembly.GetManifestResourceStream("Minseg.Core.BuildPolicy.ps1")!)
        using(var script=File.Create(Path.Combine(output,"BuildPolicy.ps1")))resource.CopyTo(script);
        var families=Fonts.GetFontFamilies(new Uri("pack://application:,,,/MINSEG-Control;component/Assets/"));
        Console.WriteLine("Fuentes incluidas: "+string.Join(", ",families.Select(f=>f.Source)));
        Console.WriteLine("Ventana y pestañas renderizadas. Datos de ejemplo; no se hicieron cambios al equipo.");
        app.Shutdown();return 0;
    }
    private static int CheckResource(string sample,string output)
    {
        // Never execute the sample: exercise cleanup on a new, isolated copy only.
        var original=new BinaryInspector().Read(Path.GetFullPath(sample));
        if(SafetyRules.Identify(original)!=Product.Wps)throw new IOException("La muestra debe ser un binario WPS firmado.");
        var fixture=Path.Combine(Path.GetFullPath(output),Guid.NewGuid().ToString("N"));
        var root=Path.Combine(fixture,"Documents","KingsoftData");
        var folder=Path.Combine(root,"office6","omath");var backup=Path.Combine(fixture,"backups");
        Directory.CreateDirectory(folder);Directory.CreateDirectory(backup);
        var copy=Path.Combine(folder,"component.exe");File.Copy(original.Path,copy,false);
        var document=Path.Combine(folder,"contrato.docx");File.WriteAllText(document,"documento conservado");
        var method=typeof(SafeFileCleaner).GetMethod("PreserveAndDeleteKingsoftResource",BindingFlags.Static|BindingFlags.NonPublic)!;
        var saved=(string)method.Invoke(null,[copy,original.Sha256,backup,root])!;
        if(File.Exists(copy)||File.ReadAllText(document)!="documento conservado")throw new IOException("No se cumplió la separación de recurso y documento.");
        var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(saved)));
        if(hash!=original.Sha256||new BinaryInspector().Read(original.Path).Sha256!=original.Sha256)throw new IOException("La muestra o el respaldo cambiaron.");
        Console.WriteLine("Recurso firmado: copia limpiada y respaldo idéntico. Documento y muestra original conservados. No se ejecutó el EXE.");
        return 0;
    }

    private static IEnumerable<T> VisualChildren<T>(DependencyObject parent) where T:DependencyObject
    {
        for(int i=0;i<VisualTreeHelper.GetChildrenCount(parent);i++)
        {
            var child=VisualTreeHelper.GetChild(parent,i);if(child is T typed)yield return typed;
            foreach(var nested in VisualChildren<T>(child))yield return nested;
        }
    }

    private static void Render(FrameworkElement surface,int width,int height,string output)
    {
        surface.Dispatcher.Invoke(()=>{},DispatcherPriority.DataBind);
        surface.Measure(new Size(width,height));surface.Arrange(new Rect(0,0,width,height));surface.UpdateLayout();
        surface.Dispatcher.Invoke(()=>{},DispatcherPriority.Render);surface.UpdateLayout();
        // DataGrid settles column widths in a queued layout pass after its first expansion.
        surface.Dispatcher.Invoke(()=>{},DispatcherPriority.ContextIdle);surface.UpdateLayout();
        var bitmap=new RenderTargetBitmap(width,height,96,96,PixelFormats.Pbgra32);bitmap.Render(surface);
        var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bitmap));using var file=File.Create(output);png.Save(file);
    }

    private static int Probe(string destination)
    {
        Directory.CreateDirectory(destination);var lines=new List<string>();var watch=System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var device=DeviceInventory.Read();lines.Add("Inventario de equipo: correcto");
            var scan=InstallationScan.Read(device);lines.Add($"Detección rápida: {scan.Installed.Count} instalaciones, {scan.Warnings.Count} avisos, completa={scan.Complete}");
            lines.Add($"Tiempo de detección: {watch.ElapsedMilliseconds} ms");
            var findings=new List<Finding>();var warnings=new List<string>();
            PersistenceScanner.Add(device,findings,warnings);lines.Add("Revisión opcional de inicios: "+string.Join("; ",warnings));
            var office=OfficeRecovery.Read(device);lines.Add(office.Summary+"; política="+office.PolicyState+"; avisos="+office.Warnings.Count);
        }
        catch(Exception ex){lines.Add(ErrorDetails.Diagnostic(ex,"Prueba local de solo lectura"));File.WriteAllLines(Path.Combine(destination,"lectura.txt"),lines);return 1;}
        File.WriteAllLines(Path.Combine(destination,"lectura.txt"),lines);Console.WriteLine(string.Join("\n",lines));return 0;
    }
}
