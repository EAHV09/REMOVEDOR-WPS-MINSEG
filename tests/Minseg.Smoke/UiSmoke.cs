using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Minseg.App;
using Minseg.Core;

internal static class UiSmoke
{
    [STAThread]
    private static int Main(string[] args)
    {
        try { Run(Path.GetFullPath(args.Single())); return 0; }
        catch(Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
    private static void Check(bool condition,string message)
    { if(!condition)throw new InvalidOperationException(message); }
    private static void Run(string output)
    {
        Directory.CreateDirectory(output);
        var app=(App)Activator.CreateInstance(typeof(App),BindingFlags.Instance|BindingFlags.NonPublic,null,[true],null)!;
        app.InitializeComponent();AppTheme.Apply(true);
        var window=new MainWindow();var model=(MainViewModel)window.DataContext;
        Check(window.FindName("ScanAction") is Button,"Falta la acción Escanear en la pantalla sencilla.");
        var advanced=(Expander)window.FindName("AdvancedOptions");
        Check(!advanced.IsExpanded,"Las opciones avanzadas deben abrir plegadas.");
        Check(window.FindName("AnyDeskAction")==null,"La edición WPS no debe mostrar acciones de AnyDesk.");
        model.SetDevice(new("MINSEG-PRUEBA","Windows 11 Enterprise","X64","MINSEG\\PRUEBA","S-1-0-0",@"C:\Users\PRUEBA","MINSEG\\PRUEBA",false,1,
            [new("Ethernet","Ethernet","Up","192.0.2.10","02:00:00:00:00:01")]));
        model.Department="Informática";
        var installed=new InstalledApp(Product.Wps,"WPS Office","12.1","Kingsoft","HKLM/fixture",@"C:\Program Files\Kingsoft","",true);
        var other=new InstalledApp(Product.AnyDesk,"AnyDesk","9","AnyDesk","HKLM/other",@"C:\Program Files\AnyDesk","",true);
        model.SetInventory(new(DateTimeOffset.Now,[],[],[],true));
        var otherUser=installed with{RegistryPath="Users|Registry64|S-1-5-21-123/fixture",Location=@"D:\Aplicaciones\WPS-otra-cuenta",MachineScope=false,OwnerSid="S-1-5-21-123"};
        model.SetScanAndInventory(new(DateTimeOffset.Now,[],[otherUser,other],["Otro perfil no se pudo leer."],false,"Perfiles registrados."));
        Check(InstallationScan.State(model.Inventory,Product.Wps)==InstallationState.Found,"El resumen perdió la instalación de otra cuenta detectada por el escaneo.");
        Check(model.Inventory!.Warnings.Contains("Otro perfil no se pudo leer.")&&!model.Inventory.Complete,"El resumen perdió los avisos de los perfiles.");
        Check(model.Inventory.Installed.Count==1&&model.Scan!.Installed.Single()==otherUser,"El escaneo y el resumen tienen distinto alcance.");
        var findings=new Finding[]{
            new(Product.Wps,FindingKind.Startup,"WPS Cloud","User|fixture",Trust.Review,"Destino pendiente de comprobar."),
            new(Product.Wps,FindingKind.Residue,"Caché WPS",@"C:\ProgramData\Kingsoft\cache",Trust.Review,"Carpeta de ejemplo."),
            new(Product.Wps,FindingKind.PersonalData,"Documentos",@"C:\Users\PRUEBA\Documents\WPSDrive",Trust.Protected,"Documentos conservados."),
            new(Product.AnyDesk,FindingKind.Binary,"AnyDesk.exe",@"C:\Program Files\AnyDesk\AnyDesk.exe",Trust.Review,"Fuera del alcance.")};
        model.SetInventory(new(DateTimeOffset.Now,findings,[installed,other],[],true));
        model.SetScan(new(DateTimeOffset.Now,findings,[installed,other],[],true,"Datos de ejemplo."));
        Check(model.Inventory!.Installed.All(x=>x.Product==Product.Wps),"El inventario WPS muestra otro producto.");
        Check(model.Scan!.Findings.All(x=>x.Product==Product.Wps),"El resultado WPS permite seleccionar otro producto.");
        model.SetOffice(new([new(".docx","Word.Document.12","Word",@"C:\Office\WINWORD.EXE","Word.Document.12"){CurrentExecutable=@"C:\Office\WINWORD.EXE",CurrentExecutableExists=true}],
            [],true,true,"GpoPending"));
        model.Status="Vista de prueba · datos de ejemplo";
        var surface=(FrameworkElement)window.Content;
        surface.DataContext=model;
        System.Windows.Documents.TextElement.SetFontFamily(surface,window.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(surface,window.FontSize);
        surface.SetResourceReference(Panel.BackgroundProperty,"Canvas");
        foreach(bool dark in new[]{true,false})
        {
            if(AppTheme.IsDark!=dark)
                typeof(MainWindow).GetMethod("ToggleTheme",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,[window,new RoutedEventArgs()]);
            Check((string)((Button)window.FindName("ThemeToggle")).Content==(dark?"Modo claro":"Modo oscuro"),"El cambio de tema no actualizó su botón.");
            foreach(var size in new[]{(1120,700),(1000,590)})
            {
                Render(surface,size.Item1,size.Item2,Path.Combine(output,$"inicio-{(dark?"negro":"claro")}-{size.Item1}.png"));
                foreach(var name in new[]{"ScanAction","WpsAction","ThemeToggle","StatusLabel","AdvancedOptions"})
                {
                    var control=(FrameworkElement)window.FindName(name);
                    var rect=control.TransformToAncestor(surface).TransformBounds(new Rect(0,0,control.ActualWidth,control.ActualHeight));
                    Check(rect.Left>=0&&rect.Top>=0&&rect.Right<=size.Item1+1&&rect.Bottom<=size.Item2+1,name+" queda fuera de pantalla.");
                }
            }
        }
        if(!AppTheme.IsDark)typeof(MainWindow).GetMethod("ToggleTheme",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,[window,new RoutedEventArgs()]);
        var color=((SolidColorBrush)window.Background).Color;
        Check(color.R<5&&color.G<5&&color.B<5,"El modo oscuro tiene un tinte de color, no negro.");
        var before=model.RemovalResult;
        typeof(MainWindow).GetMethod("ToggleTheme",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,[window,new RoutedEventArgs()]);
        Check(!AppTheme.IsDark&&model.RemovalResult==before&&!model.Busy,"Cambiar el tema alteró una operación.");
        model.Busy=true;
        Render(surface,1000,590,Path.Combine(output,"escaneando.png"));
        Check(!((Button)window.FindName("WpsAction")).IsEnabled,"Desinstalar sigue habilitado mientras hay una operación.");
        model.Busy=false;
        if(!AppTheme.IsDark)typeof(MainWindow).GetMethod("ToggleTheme",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,[window,new RoutedEventArgs()]);
        advanced.IsExpanded=true;
        Render(surface,1120,900,Path.Combine(output,"opciones-negro.png"));
        typeof(MainWindow).GetMethod("ToggleTheme",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,[window,new RoutedEventArgs()]);
        Render(surface,1120,900,Path.Combine(output,"opciones-claro.png"));
        model.SetInventory(new(DateTimeOffset.Now,[],[],["Registro inaccesible"],false));
        Check(InstallationScan.State(model.Inventory,Product.Wps)==InstallationState.Unknown,"Un error de lectura se muestra como ausencia de WPS.");
        model.RemovalResult="WPS desinstalado; verificación pendiente.";
        var method=typeof(MainWindow).GetMethod("RunOffice",BindingFlags.Instance|BindingFlags.NonPublic)!;
        ((Task)method.Invoke(window,["Comprobar Office",new Func<Task>(()=>Task.FromException(new IOException("Office no disponible")))])!).GetAwaiter().GetResult();
        Check(model.RemovalResult=="WPS desinstalado; verificación pendiente."&&model.OfficeFeedback.Contains("Office no disponible"),"Un error Office ocultó la desinstalación.");
        advanced.IsExpanded=false;
        Render(surface,1120,700,Path.Combine(output,"resultado-pendiente.png"));
        foreach(var asset in new[]{"app.ico","app-mark.png","minseg-seal.png","minseg-wordmark.png","cibercom.png"})
            Check(new BitmapImage(new Uri("pack://application:,,,/MINSEG-Control;component/Assets/"+asset)).PixelWidth>0,"Falta el recurso "+asset);
        Check(Fonts.GetFontFamilies(new Uri("pack://application:,,,/MINSEG-Control;component/Assets/")).Count>=2,"Faltan fuentes.");
        Console.WriteLine("8 vistas renderizadas. Tema, alcance WPS, controles, errores y recursos comprobados. Sin escanear ni modificar el equipo.");
        app.Shutdown();
    }
    private static void Render(FrameworkElement surface,int width,int height,string output)
    {
        surface.Dispatcher.Invoke(()=>{},DispatcherPriority.DataBind);
        surface.Measure(new Size(width,height));surface.Arrange(new Rect(0,0,width,height));surface.UpdateLayout();
        surface.Dispatcher.Invoke(()=>{},DispatcherPriority.Render);
        surface.Dispatcher.Invoke(()=>{},DispatcherPriority.ContextIdle);surface.UpdateLayout();
        var bitmap=new RenderTargetBitmap(width,height,96,96,PixelFormats.Pbgra32);bitmap.Render(surface);
        var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bitmap));using var file=File.Create(output);png.Save(file);
    }
}
