namespace Minseg.Core;

internal static class OfficeDiscovery
{
    internal static bool IsOfficeProgId(string progId)=>System.Text.RegularExpressions.Regex.IsMatch(progId,
        @"^(Word|Excel|PowerPoint|Outlook|Access|OneNote|Publisher|Visio|MSProject)\.",System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    internal static OfficeAssociation? Registered(string registration,string identifier,string progId,string command,BinaryIdentity? identity,string version)
    {
        var executable=PathSafety.ExecutableFromCommand(command);
        if(executable==null||!OfficeAssociationRules.Allowed(identifier,executable)||identity?.SignatureValid!=true||
            !identity.Signer.Equals("Microsoft Corporation",StringComparison.OrdinalIgnoreCase)||
            !identity.OriginalName.Equals(Path.GetFileName(executable),StringComparison.OrdinalIgnoreCase)||
            !identity.Path.Equals(Path.GetFullPath(executable),StringComparison.OrdinalIgnoreCase)||
            !System.Text.RegularExpressions.Regex.IsMatch(progId,@"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$"))return null;
        return new(identifier.ToLowerInvariant(),progId,OfficeAssociationRules.Apps[Path.GetFileName(executable)].Name,executable,null)
            {RegisteredApplication=registration,DetectedVersion=version};
    }
    internal static IReadOnlyList<OfficeAssociation> Select(IEnumerable<OfficeAssociation> candidates,ICollection<string> warnings,out bool complete)
    {
        complete=true;var selected=new List<OfficeAssociation>();
        foreach(var group in candidates.GroupBy(a=>a.Identifier,StringComparer.OrdinalIgnoreCase))
        {
            // Same ProgID can resolve differently in the two registry views. Do not discard that conflict.
            var unique=group.DistinctBy(a=>a.ProgId+"|"+a.Executable,StringComparer.OrdinalIgnoreCase).ToArray();
            if(unique.Length==1)selected.Add(unique[0]);
            else{complete=false;warnings.Add(group.Key+": varias instalaciones de Office compiten por este formato; no se programa automáticamente.");}
        }
        return selected.OrderBy(a=>a.Application).ThenBy(a=>a.Identifier).ToArray();
    }
}
