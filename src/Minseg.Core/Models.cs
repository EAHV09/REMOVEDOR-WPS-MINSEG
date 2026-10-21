namespace Minseg.Core;

public enum Product { Wps, AnyDesk }
public enum FindingKind { Installation, Binary, Service, Task, Startup, Residue, PersonalData, Shortcut, Directory, Registry }
public enum Trust { Review, Confirmed, Protected }
public sealed record BinaryIdentity(string Path, string ProductName, string Company, string OriginalName,
    string Signer, bool SignatureValid, string Sha256, long Length,int? TrustStatus=null);
public sealed record Finding(Product Product, FindingKind Kind, string Name, string Location,
    Trust Trust, string Detail, BinaryIdentity? Identity = null, string? Reference = null,string? ContentHash=null);
public sealed record InstalledApp(Product Product, string Name, string Version, string Publisher,
    string RegistryPath, string Location, string UninstallCommand, bool MachineScope,
    string? MsiCode = null,bool LocationInferred=false,string? OwnerSid=null);
public sealed record NetworkAdapter(string Name, string Type, string Status, string Addresses, string Mac);
public sealed record DeviceInfo(string Computer, string Windows, string Architecture, string User,
    string UserSid, string ProfilePath, string Operator, bool Administrator, int SessionId,
    IReadOnlyList<NetworkAdapter> Adapters);
public sealed record ScanResult(DateTimeOffset CapturedAt, IReadOnlyList<Finding> Findings,
    IReadOnlyList<InstalledApp> Installed, IReadOnlyList<string> Warnings, bool Complete,string Scope="Ubicaciones habituales y persistencia del equipo y del usuario conectado.",IReadOnlySet<Product>? SelectedProducts=null);
public sealed record CommandSpec(string Executable, IReadOnlyList<string> Arguments);
public sealed record OperationEntry(DateTimeOffset Time, string Product, string Action, string Target,
    string Status, string Detail);

public static class ProductNames
{
    public static string Display(this Product product) => product == Product.Wps ? "WPS Office" : "AnyDesk";
}
