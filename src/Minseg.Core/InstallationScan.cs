namespace Minseg.Core;

public enum InstallationState { Unknown, Found, NotFound }

public static class InstallationScan
{
    // This reports registration, not the absence of portable files or other user profiles.
    public static InstallationState State(ScanResult? scan,Product product)
        =>scan?.Installed.Any(a=>a.Product==product)==true?InstallationState.Found:
          scan?.Complete==true?InstallationState.NotFound:InstallationState.Unknown;

    public static ScanResult Read(DeviceInfo device)
    {
        var warnings=new List<string>();
        if(string.IsNullOrEmpty(device.UserSid))warnings.Add("No se pudo comprobar el usuario conectado. Solo se revisaron las instalaciones del equipo.");
        var installed=InstalledPrograms.Read(device,warnings);
        var findings=installed.Select(a=>new Finding(a.Product,FindingKind.Installation,a.Name,a.Location,Trust.Review,
            "Instalación registrada. Se comprobará el desinstalador antes de abrirlo.",Reference:a.RegistryPath)).ToArray();
        return new(DateTimeOffset.Now,findings,installed,warnings,warnings.Count==0);
    }
}
