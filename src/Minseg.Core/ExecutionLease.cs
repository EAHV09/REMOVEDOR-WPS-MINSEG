using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Minseg.Core;

// Locks the executable and its parent chain while identity and ACLs are checked and CreateProcess runs.
internal sealed class ExecutionLease:IDisposable
{
    private readonly List<SafeFileHandle> handles=[];
    public static ExecutionLease Acquire(string path,bool elevated)
    {
        var lease=new ExecutionLease();
        try
        {
            PathSafety.RequireNoReparse(path);
            var parents=new List<string>();for(var directory=Path.GetDirectoryName(path);directory!=null;directory=Path.GetDirectoryName(directory))parents.Add(directory);
            parents.Reverse();
            foreach(var directory in parents)lease.Lock(directory,true);
            lease.Lock(path,false);PathSafety.RequireNoReparse(path);
            if(elevated)
            {
                var anchors=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)};
                var anchor=anchors.FirstOrDefault(root=>SafetyRules.IsContained(root,path))
                    ??throw new UnauthorizedAccessException("El desinstalador elevado debe estar en Archivos de programa. Revisa las instalaciones en rutas especiales con TI.");
                foreach(var directory in parents.Where(p=>p.Equals(anchor,StringComparison.OrdinalIgnoreCase)||SafetyRules.IsContained(anchor,p)))
                    if(!SecureWorkspace.IsRestricted(directory))throw new UnauthorizedAccessException("Una carpeta del desinstalador permite cambios de usuarios. No se ejecutará como administrador.");
                if(!SecureWorkspace.IsRestricted(path))throw new UnauthorizedAccessException("El desinstalador tiene permisos inseguros.");
            }
            return lease;
        }
        catch{lease.Dispose();throw;}
    }
    private void Lock(string path,bool directory)
    {
        var handle=CreateFile(path,directory?0x80u:0x80000000u,directory?3u:1u,IntPtr.Zero,3,directory?0x02200000u:0x00200000u,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new IOException("No se pudo bloquear la ruta para comprobar el desinstalador.",new Win32Exception(Marshal.GetLastWin32Error()));}
        handles.Add(handle);
    }
    public void Dispose(){foreach(var handle in handles)handle.Dispose();handles.Clear();}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
}
