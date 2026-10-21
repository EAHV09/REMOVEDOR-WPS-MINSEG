using System.Security.Cryptography;
using System.Text;
namespace Minseg.Core;

internal static class OfficePreparedFile
{
    internal static string SaveRecoverable(string path,string xml,OfficeFileState state,Action<OfficeFileState> persist,bool restricted=true)
    {
        PathSafety.RequireNoReparse(Path.GetDirectoryName(path)!);
        string? existing=null;
        if(File.Exists(path))
        {
            PathSafety.RequireNoReparse(path);
            if(restricted&&(!SecureWorkspace.IsRestricted(Path.GetDirectoryName(path)!)||!SecureWorkspace.IsRestricted(path)))throw new IOException("El XML no está protegido.");
            existing=Hash(path);
            if(!state.Accepts(existing))throw new IOException("El XML existente no pertenece a esta preparación o cambió. Se conserva.");
        }
        var next=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(xml)));
        persist(new(existing,next));
        var hash=Save(path,xml,existing,restricted);
        persist(new(hash,null));
        return hash;
    }
    internal static string Hash(string path)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    internal static string Save(string path,string xml,string? expectedHash,bool restricted=true)
    {
        var parent=Path.GetDirectoryName(path)!;
        PathSafety.RequireNoReparse(parent);
        if(restricted&&!SecureWorkspace.IsRestricted(parent))throw new UnauthorizedAccessException("La carpeta Office no tiene permisos seguros.");
        var exists=File.Exists(path);
        void CheckPrevious()
        {
            if(File.Exists(path)!=exists)throw new IOException("El archivo Office cambió durante la preparación.");
            if(!exists)return;
            PathSafety.RequireNoReparse(path);
            if((restricted&&!SecureWorkspace.IsRestricted(path))||expectedHash==null||Hash(path)!=expectedHash)
                throw new IOException("El archivo Office existente no pertenece a esta preparación o fue modificado. Se conserva.");
        }
        CheckPrevious();
        var bytes=new UTF8Encoding(false).GetBytes(xml);
        var hash=Convert.ToHexString(SHA256.HashData(bytes));
        if(exists&&hash==expectedHash)return hash;
        var pending=Path.Combine(parent,Guid.NewGuid().ToString("N")+".tmp");
        using(var output=new FileStream(pending,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
        {output.Write(bytes);output.Flush(true);}
        if(restricted&&!SecureWorkspace.IsRestricted(pending))throw new UnauthorizedAccessException("El XML no tiene permisos seguros.");
        CheckPrevious();
        // Publish atomically. Keep the old XML as a backup; never replace an unowned file.
        if(exists)File.Replace(pending,path,Path.Combine(parent,Guid.NewGuid().ToString("N")+".previous.xml"));
        else File.Move(pending,path,false);
        PathSafety.RequireNoReparse(path);
        if(Hash(path)!=hash||(restricted&&!SecureWorkspace.IsRestricted(path)))throw new IOException("No se pudo verificar el XML preparado.");
        return hash;
    }
}
