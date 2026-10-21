using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace Minseg.Core;
public static class SafeFileCleaner
{
    internal static string PreserveAndDeleteKingsoftResource(string path,string hash,string backup,string root)
        =>PreserveAndDeleteCore(path,hash,backup,root);
    public static bool DeleteEmptyDirectory(string path,string root)
    {
        if((SafetyRules.IsPersonalData(path)&&!KingsoftDataResources.DirectoryAllowed(path,root))||!SafetyRules.IsLocalPath(root)
            ||!(Path.GetFullPath(path).Equals(Path.GetFullPath(root),StringComparison.OrdinalIgnoreCase)||SafetyRules.IsContained(root,path)))throw new IOException("Carpeta fuera del alcance.");
        PathSafety.RequireNoReparse(path);
        using var handle=CreateFile(path,0x00010000|0x80,1|2,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(handle.IsInvalid)throw new IOException("Carpeta ocupada o sin permiso.",new Win32Exception(Marshal.GetLastWin32Error()));
        if(!GetFileInformationByHandle(handle,out var info)||(info.Attributes&0x400)!=0||(info.Attributes&0x10)==0)throw new IOException("No es una carpeta local comprobada.");
        var final=new StringBuilder(32768);
        if(GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0)==0)throw new IOException("Ruta de carpeta no comprobable.");
        var real=final.ToString();if(real.StartsWith(@"\\?\"))real=real[4..];
        if(!Path.GetFullPath(path).Equals(real,StringComparison.OrdinalIgnoreCase))throw new IOException("La carpeta cambió.");
        if(Directory.EnumerateFileSystemEntries(path).Any())return false;
        var disposition=new FileDisposition{Delete=true};
        if(!SetFileInformationByHandle(handle,4,ref disposition,(uint)Marshal.SizeOf<FileDisposition>()))throw new IOException("Windows no permitió eliminar la carpeta vacía.");
        return true;
    }
    public static string PreserveAndDelete(string path,string expectedHash,string backupDirectory)
        =>PreserveAndDeleteCore(path,expectedHash,backupDirectory,null);
    private static string PreserveAndDeleteCore(string path,string expectedHash,string backupDirectory,string? resourceRoot)
    {
        if(resourceRoot!=null?!KingsoftDataResources.ResourcePath(path,resourceRoot):SafetyRules.IsPersonalData(path)) throw new IOException("Archivo personal: se conserva.");
        PathSafety.RequireNoReparse(path);PathSafety.RequireNoReparse(backupDirectory);
        BinaryIdentity? resourceIdentity=null;
        if(resourceRoot!=null&&new[]{".exe",".dll"}.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase))
        {
            // Authenticode APIs open by path. Verify before the DELETE lease, then bind that proof
            // to the exact bytes read from the locked handle below (including the scan hash).
            resourceIdentity=new BinaryInspector().Read(path);
            if(SafetyRules.Identify(resourceIdentity)!=Product.Wps)throw new IOException("Recurso sin firma WPS comprobada.");
        }
        // ASVS 15.4.2: read, hash and delete the SAME locked handle, not a later path lookup.
        using var handle=CreateFile(path,0x80000000|0x00010000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        if(handle.IsInvalid) throw new IOException("Archivo ocupado o sin permiso. Se conserva.",new Win32Exception(Marshal.GetLastWin32Error()));
        if(!GetFileInformationByHandle(handle,out var info)||info.Links!=1||(info.Attributes&0x400)!=0)
            throw new IOException("Enlace o archivo no comprobable: se conserva.");
        var final=new StringBuilder(32768);
        if(GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0)==0) throw new IOException("No se pudo comprobar la ruta real.");
        var real=final.ToString();if(real.StartsWith(@"\\?\"))real=real[4..];
        if(!Path.GetFullPath(path).Equals(real,StringComparison.OrdinalIgnoreCase)) throw new IOException("La ruta cambió: se conserva.");
        using var source=new FileStream(handle,FileAccess.Read);
        if(source.Length>512L*1024*1024)throw new IOException("Archivo demasiado grande: se conserva.");
        var current=Convert.ToHexString(SHA256.HashData(source));
        if(!current.Equals(expectedHash,StringComparison.OrdinalIgnoreCase)) throw new IOException("El archivo cambió después del análisis. Vuelve a analizar.");
        if(resourceIdentity!=null&&resourceIdentity.Sha256!=current)throw new IOException("El recurso cambió tras comprobar su firma.");
        if(resourceRoot!=null&&resourceIdentity==null&&!KingsoftDataResources.ContentAllowed(path,resourceRoot,source))throw new IOException("Contenido no comprobado: se conserva.");
        source.Position=0;
        var backup=Path.Combine(backupDirectory,Guid.NewGuid().ToString("N")+".saved");
        using(var destination=new FileStream(backup,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { source.CopyTo(destination);destination.Flush(true); }
        // Only mark this handle for deletion after a successful durable backup. Never recurse or change ACLs.
        var disposition=new FileDisposition{Delete=true};
        if(!SetFileInformationByHandle(handle,4,ref disposition,(uint)Marshal.SizeOf<FileDisposition>()))
            throw new IOException("Se guardó respaldo, pero Windows no permitió limpiar el archivo.");
        return backup;
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileDisposition { [MarshalAs(UnmanagedType.Bool)]public bool Delete; }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo { public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInfo info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetFileInformationByHandle(SafeFileHandle file,int type,ref FileDisposition info,uint size);
}
