namespace Minseg.Core;
public static class ResidueRules
{
    public static bool Eligible(string path,BinaryIdentity anchor,Product product)
    {
        if(SafetyRules.Identify(anchor)!=product||SafetyRules.IsPersonalData(path)||!SafetyRules.IsLocalPath(path))return false;
        var folder=Path.GetDirectoryName(anchor.Path)!;
        if(!string.Equals(folder,Path.GetDirectoryName(path),StringComparison.OrdinalIgnoreCase))return false;
        var name=Path.GetFileName(folder);
        var dedicated=product==Product.AnyDesk?name.Equals("AnyDesk",StringComparison.OrdinalIgnoreCase)||name.StartsWith("ad_",StringComparison.OrdinalIgnoreCase)
            :new[]{"WPS Office","WPS","office6","Kingsoft"}.Contains(name,StringComparer.OrdinalIgnoreCase);
        return dedicated&&new[]{".log",".trace",".tmp",".cache",".conf"}.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase);
    }
}
