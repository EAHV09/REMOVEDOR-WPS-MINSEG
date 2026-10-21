namespace Minseg.Core;

public static class PathSafety
{
    public static void RequireNoReparse(string path)
    {
        if(!SafetyRules.IsLocalPath(path)) throw new IOException("Ruta no admitida.");
        var current=Path.GetFullPath(path);
        while(current.Length>3)
        {
            if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0) throw new IOException("Se conserva: enlace o archivo de nube.");
            current=Path.GetDirectoryName(current)??"";
        }
    }

    public static bool IsSafeExistingPath(string path)
    {
        try { RequireNoReparse(path);return true; }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    public static string? ExecutableFromCommand(string command)
    {
        var text=Environment.ExpandEnvironmentVariables(command.Trim());
        if(text.StartsWith('"'))
        {
            int end=text.IndexOf('"',1);
            if(end<0||(end+1<text.Length&&!char.IsWhiteSpace(text[end+1]))) return null;
            var path=text[1..end];
            return SafetyRules.IsLocalPath(path)&&Path.GetExtension(path).Equals(".exe",StringComparison.OrdinalIgnoreCase)?path:null;
        }
        // Windows may resolve an unquoted spaced path to a different executable (e.g. C:\Program.exe).
        // Accept a whole token, never truncate at the first occurrence of '.exe'.
        int endOfToken=0;while(endOfToken<text.Length&&!char.IsWhiteSpace(text[endOfToken]))endOfToken++;
        var result=text[..endOfToken];
        return SafetyRules.IsLocalPath(result)&&!result.Contains('"')&&Path.GetExtension(result).Equals(".exe",StringComparison.OrdinalIgnoreCase)?result:null;
    }
}
