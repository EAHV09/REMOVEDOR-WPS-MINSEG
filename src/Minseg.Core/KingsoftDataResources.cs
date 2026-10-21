using System.Buffers.Binary;
using System.Security.Cryptography;
namespace Minseg.Core;

// A narrow exception to the personal-data guard. Unknown data is never a cleanup candidate.
internal static class KingsoftDataResources
{
    internal const string Marker="kingsoft-resource|";
    internal static bool IsRoot(string root)
    {
        if(!SafetyRules.IsLocalPath(root))return false;
        var full=Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return Path.GetFileName(full).Equals("KingsoftData",StringComparison.OrdinalIgnoreCase)
            &&new[]{"Documents","Documentos"}.Contains(Path.GetFileName(Path.GetDirectoryName(full)),StringComparer.OrdinalIgnoreCase)
            &&!full.Split('\\').Any(p=>p.StartsWith("OneDrive",StringComparison.OrdinalIgnoreCase)||p.Equals("WPSDrive",StringComparison.OrdinalIgnoreCase));
    }
    internal static bool DirectoryAllowed(string path,string root)
    {
        if(!IsRoot(root))return false;
        if(Path.GetFullPath(path).Equals(Path.GetFullPath(root),StringComparison.OrdinalIgnoreCase))return true;
        if(!SafetyRules.IsContained(root,path))return false;
        var parts=Path.GetRelativePath(root,path).Split('\\');
        return parts[0].Equals("office6",StringComparison.OrdinalIgnoreCase)&&(parts.Length==1||new[]{"KingsoftUE","mtfont","omath"}.Contains(parts[1],StringComparer.OrdinalIgnoreCase))
            &&!parts.Skip(1).Any(p=>new[]{"backup","backups","recovery","recover","Documents","Documentos"}.Contains(p,StringComparer.OrdinalIgnoreCase));
    }
    internal static bool ResourcePath(string path,string root)
        =>DirectoryAllowed(Path.GetDirectoryName(path)??"",root)
            &&Path.GetRelativePath(root,path).Split('\\').Length>=3
            &&new[]{".ttf",".otf",".exe",".dll"}.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase);
    internal static bool ContentAllowed(string path,string root,Stream stream)
    {
        if(!ResourcePath(path,root)||stream.Length>100L*1024*1024)return false;
        var ext=Path.GetExtension(path);
        if(ext.Equals(".exe",StringComparison.OrdinalIgnoreCase)||ext.Equals(".dll",StringComparison.OrdinalIgnoreCase))
            return SafetyRules.Identify(new BinaryInspector().Read(path))==Product.Wps;
        // Validate a bounded sfnt table directory, not just the extension or a four-byte magic.
        Span<byte> header=stackalloc byte[12];stream.Position=0;
        if(stream.Read(header)!=12)return false;
        uint magic=BinaryPrimitives.ReadUInt32BigEndian(header);
        if(magic!=0x00010000&&magic!=0x4F54544F)return false;
        int tables=BinaryPrimitives.ReadUInt16BigEndian(header[4..]);
        if(tables<1||tables>256||stream.Length<12+16*tables)return false;
        Span<byte> entry=stackalloc byte[16];
        for(int i=0;i<tables;i++)
        {
            if(stream.Read(entry)!=16)return false;
            uint offset=BinaryPrimitives.ReadUInt32BigEndian(entry[8..]),length=BinaryPrimitives.ReadUInt32BigEndian(entry[12..]);
            if(offset<12+16*tables||(ulong)offset+length>(ulong)stream.Length)return false;
        }
        return true;
    }
    internal static bool IsFinding(Finding f)=>f.Product==Product.Wps&&f.Reference?.StartsWith(Marker,StringComparison.Ordinal)==true
        &&f.Kind is FindingKind.Residue or FindingKind.Directory;
    internal static void Add(string root,List<Finding> findings,List<string> warnings,Func<bool> more)
    {
        if(!IsRoot(root))return;
        var pending=new Stack<string>();pending.Push(root);
        while(pending.TryPop(out var folder)&&more())
        {
            try
            {
                PathSafety.RequireNoReparse(folder);
                findings.Add(new(Product.Wps,FindingKind.Directory,Path.GetFileName(folder),folder,Trust.Confirmed,"Se elimina solo si está vacía; los documentos permanecen.",Reference:Marker+root));
                foreach(var path in Directory.EnumerateFileSystemEntries(folder))
                {
                    if(!more())return;
                    var attr=File.GetAttributes(path);
                    if((attr&FileAttributes.ReparsePoint)!=0)
                    {findings.Add(new(Product.Wps,FindingKind.PersonalData,Path.GetFileName(path),path,Trust.Protected,"Enlace o nube: conservado."));continue;}
                    if((attr&FileAttributes.Directory)!=0)
                    {
                        if(DirectoryAllowed(path,root))pending.Push(path);
                        else findings.Add(new(Product.Wps,FindingKind.PersonalData,Path.GetFileName(path),path,Trust.Protected,"Carpeta ajena a los componentes técnicos: conservada."));
                        continue;
                    }
                    if(ResourcePath(path,root))
                    {
                        using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                        if(ContentAllowed(path,root,input))
                        {
                            input.Position=0;findings.Add(new(Product.Wps,FindingKind.Residue,Path.GetFileName(path),path,Trust.Confirmed,"Recurso técnico comprobado en KingsoftData; se respalda antes de borrar.",Reference:Marker+root,ContentHash:Convert.ToHexString(SHA256.HashData(input))));continue;
                        }
                    }
                    findings.Add(new(Product.Wps,FindingKind.PersonalData,Path.GetFileName(path),path,Trust.Protected,"Documento, recuperación o contenido no identificado: conservado en su lugar."));
                }
            }
            catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException){ }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or CryptographicException or System.ComponentModel.Win32Exception)
            {warnings.Add("KingsoftData pendiente: "+folder+". "+ErrorDetails.Message(ex));}
        }
        var protectedPaths=findings.Where(f=>f.Kind==FindingKind.PersonalData&&SafetyRules.IsContained(root,f.Location)).Select(f=>f.Location).ToArray();
        for(int i=0;i<findings.Count;i++)
        {
            var f=findings[i];
            if(f.Kind==FindingKind.Directory&&f.Reference==Marker+root&&protectedPaths.Any(p=>SafetyRules.IsContained(f.Location,p)))
                findings[i]=f with{Kind=FindingKind.PersonalData,Trust=Trust.Protected,Detail="Carpeta conservada porque contiene documentos o datos no identificados; sus componentes técnicos se revisan por separado."};
        }
    }
}
