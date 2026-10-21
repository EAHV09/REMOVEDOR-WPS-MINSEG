using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Minseg.Core;
namespace Minseg.App;

public sealed class FindingRow:INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    public Finding Finding{get;}
    private bool selected;
    public bool Selected{get=>selected;set{selected=value;PropertyChanged?.Invoke(this,new(nameof(Selected)));}}
    public string Name=>Finding.Name;
    public string Location=>Finding.Location;
    public string Kind=>Finding.Kind switch{FindingKind.Installation=>"Instalación",FindingKind.Binary=>"Programa",FindingKind.Service=>"Servicio",FindingKind.Task=>"Tarea",FindingKind.Startup=>"Inicio",FindingKind.Residue=>"Resto",FindingKind.Shortcut=>"Acceso directo",FindingKind.Directory=>"Carpeta",FindingKind.Registry=>"Registro",_=>"Datos conservados"};
    public string Trust=>Finding.Trust switch{Minseg.Core.Trust.Confirmed=>"Comprobado",Minseg.Core.Trust.Protected=>"Protegido",_=>"Revisar"};
    public FindingRow(Finding finding)=>Finding=finding;
}
public sealed class MainViewModel:INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private string department="Sin indicar",status="Leyendo el equipo…";
    private bool busy;
    public DeviceInfo? Device{get;private set;}
    public ScanResult? Scan{get;private set;}
    public ScanResult? Inventory{get;private set;}
    public PersistenceReport? Persistence{get;private set;}
    public OfficePlan? Office{get;private set;}
    public string BuildLabel=>"Versión "+typeof(MainViewModel).Assembly.GetName().Version?.ToString(3)+" · Pruebas";
    private string removalResult="El botón desinstala y después limpia los restos comprobados. El resultado aparecerá aquí.";
    public string RemovalResult{get=>removalResult;set{removalResult=value;Notify();}}
    public string WpsPersistence=>Persistence?.Summary(Product.Wps)??"Revisando persistencia…";
    public string AnyDeskPersistence=>Persistence?.Summary(Product.AnyDesk)??"Revisando persistencia…";
    public string PersistenceDetails=>Persistence==null?"Escaneo pendiente":Persistence.Coverage+"\n\n"+
        string.Join("\n",Persistence.Findings.Select(f=>$"{f.Product.Display()} · {new FindingRow(f).Kind} · {new FindingRow(f).Trust}\n{f.Name}: {f.Location}\n{f.Detail}\n"))+string.Join("\n",Persistence.Warnings);
    public string OfficeSummary=>Office?.Summary??"Pulsa Comprobar Office para revisar la configuración.";
    private string officeFeedback="";
    public string OfficeFeedback{get=>officeFeedback;set{officeFeedback=value;Notify();}}
    public string OfficeDetail=>Office==null?"Se revisa toda la suite instalada y sus formatos compatibles.":
        Office.DomainJoined?OfficeRecovery.PolicyExplanation(Office.PolicyState):
        !Office.CanVerifyUser?"Abre la herramienta con el usuario que tiene el problema para comprobar sus formatos.":
        Office.Associations.Count>0&&Office.Matched==Office.Associations.Count?"La selección de Office y los programas de apertura coinciden. Prueba un documento; el icono por sí solo no confirma que funcione.":OfficeRecovery.PolicyExplanation(Office.PolicyState);
    public IReadOnlyList<OfficeAppChoice> OfficeApplications=>Office?.Applications??[];
    public IReadOnlyList<OfficeAssociation> OfficeFormats=>Office?.Associations??[];
    public string OfficeDetection=>Office?.DetectionSummary??"Todavía no se ha revisado Office.";
    public bool OfficeManual=>Office?.PolicyState=="Manual";
    public string OfficeButton=>OfficeManual?"Configurar Office":"Preparar Office automático";
    public string OfficeWarnings=>string.Join("\n",Office?.Warnings??[]);
    public string OfficeSteps=>Office?.DomainJoined==true?
        "1. Prepara Office automático.  2. Windows lo aplica al próximo inicio de sesión.  3. Pulsa Comprobar Office. No necesitas elegir cada aplicación. Si TI ya tiene otra política, debe integrar el XML primero.":
        OfficeDefaultsGuide.Steps(OperatingSystem.IsWindowsVersionAtLeast(10,0,22000));
    public void SetOffice(OfficePlan plan){Office=plan;Notify(null);}
    public void SetPersistence(PersistenceReport report)
    {
        var warnings=(Scan?.Warnings??[]).Concat(report.Warnings).Distinct().ToArray();
        var retained=(Scan?.Findings.Where(f=>f.Kind is FindingKind.Binary or FindingKind.Residue or FindingKind.PersonalData or FindingKind.Directory or FindingKind.Shortcut or FindingKind.Registry)??[]).ToArray();
        var coverage=retained.Length>0?Scan!.Scope+"\nPersistencia actualizada: "+report.Coverage:report.Coverage;
        var scan=new ScanResult(retained.Length>0?Scan!.CapturedAt:report.CapturedAt,retained.Concat(report.Findings).ToArray(),Inventory?.Installed??[],warnings,report.Complete&&(Scan?.Complete??true),coverage,report.SelectedProducts);
        SetScan(scan);Notify(null);
    }
    public string Computer=>Device?.Computer??"Leyendo…";
    public string ConnectedUser=>Device?.User??"Leyendo…";
    public string Department{get=>department;set{department=value;Notify();}}
    public string Ip=>Device?.Adapters.Where(a=>a.Status=="Up").SelectMany(a=>a.Addresses.Split(", ")).FirstOrDefault(a=>System.Net.IPAddress.TryParse(a,out var ip)&&ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork)
        ??Device?.Adapters.FirstOrDefault(a=>a.Status=="Up"&&a.Addresses.Length>0)?.Addresses.Split(", ")[0]??"Sin conexión";
    public string Mac=>Device?.Adapters.FirstOrDefault(a=>a.Status=="Up"&&a.Mac.Length>0)?.Mac??"No disponible";
    public string DeviceDetails=>Device==null?"Leyendo información…":$"Equipo: {Device.Computer}\nWindows: {Device.Windows} · {Device.Architecture}\nUsuario conectado: {Device.User}\nCuenta que ejecuta la herramienta: {Device.Operator}\nPermisos: {(Device.Administrator?"Administrador":"Usuario")}\nSesión: {Device.SessionId}";
    public string Status{get=>status;set{status=value;Notify();}}
    public bool Busy{get=>busy;set{busy=value;Notify();Notify(nameof(Available));}}
    public bool Available=>!Busy;
    public bool CanCancel{get;set;}
    public bool HasScan=>Scan!=null;
    public bool CanUseTools=>Device!=null;
    public bool CanElevate=>Device?.Administrator==false;
    public bool SelectWps{get;set;}=true;
    public bool SelectAnyDesk{get;set;}=true;
    private bool documentsSaved,alternateAccess,compatibilityChecked;
    public bool DocumentsSaved{get=>documentsSaved;set{documentsSaved=value;Notify();}}
    public bool AlternateAccess{get=>alternateAccess;set{alternateAccess=value;Notify();}}
    public bool CompatibilityChecked{get=>compatibilityChecked;set{compatibilityChecked=value;Notify();}}
    public string WpsSummary=>Summary(Product.Wps);
    public string AnyDeskSummary=>Summary(Product.AnyDesk);
    public string InventoryNotice=>Inventory==null?"Buscando instalaciones del equipo y del usuario…":
        Inventory.Complete?$"Última búsqueda: {Inventory.CapturedAt:HH:mm}. Revisa también los restos y las copias portátiles.":string.Join(" ",Inventory.Warnings);
    public ObservableCollection<string> Diagnostics{get;}=[];
    public string ScanNotice=>Scan==null?"Todavía no has analizado el equipo.":$"Último análisis: {Scan.CapturedAt:HH:mm}. {(Scan.Complete?"Terminó dentro del alcance elegido.":"Análisis parcial.")} "+Scan.Scope+" "+string.Join(" ",Scan.Warnings);
    public string PolicySummary{get;private set;}="Sin comprobar";
    public string PolicyDetail{get;private set;}="Consulta el estado antes de activar cambios.";
    public ObservableCollection<FindingRow> WpsFindings{get;}=[];
    public ObservableCollection<FindingRow> AnyDeskFindings{get;}=[];
    public ObservableCollection<NetworkAdapter> Adapters{get;}=[];
    public ObservableCollection<OperationEntry> Entries{get;}=[];
    public void SetDevice(DeviceInfo device){Device=device;Adapters.Clear();foreach(var adapter in device.Adapters)Adapters.Add(adapter);Notify(null);}
    public void SetScan(ScanResult scan)
    {
        scan=WpsOnly(scan);Scan=scan;Persistence=new(scan.CapturedAt,scan.Findings.Where(PersistenceReport.IsPersistence).ToArray(),scan.Warnings,scan.Complete,scan.Scope,scan.SelectedProducts);WpsFindings.Clear();AnyDeskFindings.Clear();
        foreach(var finding in scan.Findings)(finding.Product==Product.Wps?WpsFindings:AnyDeskFindings).Add(new FindingRow(finding));Notify(null);
    }
    public void InvalidateScanAfterWorker()
    {
        Diagnostics.Add("La continuación de administrador terminó y se invalidó el análisis anterior. Su informe completo está en ProgramData\\MINSEG-Control. La detección que sigue tiene su propio alcance.");
        Scan=null;Persistence=null;WpsFindings.Clear();AnyDeskFindings.Clear();Notify(null);
    }
    public void SetInventory(ScanResult scan){Inventory=WpsOnly(scan);Notify(null);}
    public void SetScanAndInventory(ScanResult scan){SetInventory(scan);SetScan(scan);}
    private static ScanResult WpsOnly(ScanResult scan)=>scan with
    {
        Findings=scan.Findings.Where(f=>f.Product==Product.Wps).ToArray(),
        Installed=scan.Installed.Where(a=>a.Product==Product.Wps).ToArray(),
        SelectedProducts=new HashSet<Product>{Product.Wps}
    };
    public string WpsReviewSummary=>Scan==null?"Pulsa Escanear equipo":
        $"{Scan.Findings.Count(f=>f.Kind!=FindingKind.PersonalData&&f.Kind!=FindingKind.Installation)} elemento(s) por revisar"+(Scan.Complete?"":" · Escaneo parcial");

    public void SetPolicy(PolicyState policy){PolicySummary=policy.Status;PolicyDetail=policy.Detail;Notify(null);}
    public void SetEntries(IEnumerable<OperationEntry> entries){Entries.Clear();foreach(var entry in entries)Entries.Add(entry);Notify(null);}
    public void Notify([CallerMemberName]string? name=null)=>PropertyChanged?.Invoke(this,new PropertyChangedEventArgs(name));
    private string Summary(Product product)=>InstallationScan.State(Inventory,product) switch
    {
        InstallationState.Found=>"Instalación encontrada",
        InstallationState.NotFound=>"Sin instalación registrada",
        _=>Inventory==null?"Buscando…":"No se pudo comprobar todo"
    };
}
