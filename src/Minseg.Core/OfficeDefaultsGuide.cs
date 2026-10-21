namespace Minseg.Core;

public static class OfficeDefaultsGuide
{
    public static string SettingsUri(string? registeredApplication,Version windows)
    {
        // Per-app links are supported only after the April 2023 Windows 11 updates.
        var supported=windows.Major==10&&(windows.Build>=22631||windows.Build==22621&&windows.Revision>=1555||windows.Build==22000&&windows.Revision>=1817);
        return supported&&!string.IsNullOrWhiteSpace(registeredApplication)
            ?"ms-settings:defaultapps?registeredAppMachine="+Uri.EscapeDataString(registeredApplication)
            :"ms-settings:defaultapps";
    }
    public static string Steps(bool windows11)=>windows11
        ?"1. Pulsa Configurar en cada aplicación con formatos pendientes. 2. En Windows elige esa aplicación para sus tipos de archivo; usa Establecer predeterminado si aparece y revisa los restantes. 3. Vuelve aquí y pulsa Comprobar Office."
        :"1. Pulsa Configurar y, en Windows, baja a Establecer valores predeterminados por aplicación. 2. Elige Word, Excel, PowerPoint y las demás aplicaciones instaladas; entra en Administrar y asigna sus formatos pendientes. 3. Vuelve aquí y pulsa Comprobar Office.";
}
