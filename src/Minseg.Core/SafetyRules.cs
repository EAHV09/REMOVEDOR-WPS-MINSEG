namespace Minseg.Core;

public static class SafetyRules
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    { "explorer.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "copilot.exe", "msedge.exe", "msedgewebview2.exe", "onedrive.exe" };
    private static readonly HashSet<string> Documents = new(StringComparer.OrdinalIgnoreCase)
    { ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm", ".csv", ".ppt", ".pptx", ".pptm", ".pdf", ".rtf", ".txt", ".wps", ".et", ".dps", ".odt", ".ods", ".odp", ".anydesk", ".mp4", ".zip", ".7z", ".bak" };
    public static bool IsLocalPath(string path) => path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1]==':' && path[2]=='\\'
        && !path[2..].Contains(':') && !path.Any(char.IsControl) && !path.Contains('*') && !path.Contains('?');

    // ASVS 5.3.2: canonical local paths, explicit directory boundary, no alternate streams.
    public static bool IsContained(string root, string candidate)
    {
        if (!IsLocalPath(root) || !IsLocalPath(candidate)) return false;
        try
        {
            var canonical = Path.GetFullPath(root).TrimEnd('\\');
            if (canonical.Length <= 3) return false;
            return Path.GetFullPath(candidate).StartsWith(canonical + "\\", StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException) { return false; }
    }

    public static bool IsPersonalData(string path)
    {
        if (Documents.Contains(Path.GetExtension(path))) return true;
        string[] reserved = ["wpsdrive", "kingsoftdata", "onedrive", "backup", "backups", "recovery", "recover", "documents", "documentos", "recordings"];
        return path.Split('\\','/').Any(part=>reserved.Any(word=>part.Equals(word,StringComparison.OrdinalIgnoreCase)
            || (word=="onedrive" && part.StartsWith("OneDrive - ",StringComparison.OrdinalIgnoreCase))));
    }

    public static Product? Identify(BinaryIdentity identity)
    {
        if (!identity.SignatureValid || ProtectedNames.Contains(identity.OriginalName) || ProtectedNames.Contains(Path.GetFileName(identity.Path))) return null;
        var publisher = identity.Signer.Trim();
        var product = identity.ProductName.Trim();
        if ((publisher.Equals("AnyDesk Software GmbH",StringComparison.OrdinalIgnoreCase)
            || publisher.Equals("philandro Software GmbH",StringComparison.OrdinalIgnoreCase))
            && (product.Contains("AnyDesk",StringComparison.OrdinalIgnoreCase) || identity.OriginalName.Equals("AnyDesk.exe",StringComparison.OrdinalIgnoreCase))) return Product.AnyDesk;
        // WPS 12.1.0.29162: checked against the vendor's signed installer and utility/uninst.exe.
        string[] wpsEditors=["WPS SOFTWARE PTE. LTD.","Kingsoft Office Software Corporation Limited","Zhuhai Kingsoft Office Software Co., Ltd.","Zhuhai Kingsoft Office Software Co.,Ltd.","KINGSOFT OFFICE SOFTWARE CORPORATION LIMITED"];
        if (wpsEditors.Contains(publisher,StringComparer.OrdinalIgnoreCase)
            && (product.StartsWith("WPS Office",StringComparison.OrdinalIgnoreCase) || product.StartsWith("Kingsoft Office",StringComparison.OrdinalIgnoreCase))) return Product.Wps;
        return null;
    }

    public static bool CanClean(BinaryIdentity identity, Product product) => Identify(identity)==product
        && !IsPersonalData(identity.Path) && IsLocalPath(identity.Path)
        && identity.Sha256.Length==64 && identity.Sha256.All(Uri.IsHexDigit)
        && new[]{".exe",".dll",".msi"}.Contains(Path.GetExtension(identity.Path),StringComparer.OrdinalIgnoreCase);

    // ASVS 1.2.5: do not pass registry commands to a shell. Only a canonical MSI GUID is accepted.
    public static CommandSpec MsiUninstall(string productCode)
    {
        if (!Guid.TryParseExact(productCode,"B",out var guid)) throw new ArgumentException("El identificador MSI no es válido.");
        return new CommandSpec(Path.Combine(Environment.SystemDirectory,"msiexec.exe"),
            ["/x",guid.ToString("B"),"/passive","/norestart","REBOOT=ReallySuppress","MSIRESTARTMANAGERCONTROL=Disable"]);
    }
}
