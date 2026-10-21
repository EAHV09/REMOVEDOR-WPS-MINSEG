using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Minseg.Core;

public sealed class BinaryInspector
{
    public BinaryIdentity Read(string path, bool requireHash=true,bool allowTrustNetwork=false)
    {
        if (!SafetyRules.IsLocalPath(path)) throw new IOException("La ruta no es local.");
        PathSafety.RequireNoReparse(path);
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length>512L*1024*1024) throw new IOException("Archivo demasiado grande para comprobarlo en esta pasada.");
        var version=FileVersionInfo.GetVersionInfo(path);
        int trust=VerifyTrust(path,true);
        // Only the executable selected for uninstall may refresh Windows' certificate chain.
        // Bulk file scans stay offline. Never downgrade a failed signature to "valid".
        if(allowTrustNetwork&&(trust is unchecked((int)0x800B010A) or unchecked((int)0x800B0109) or unchecked((int)0x80092013)))trust=VerifyTrust(path,false);
        var valid=trust==0; var signer="";
        {
            try
            {
                // LoadCertificate does not read Authenticode PE containers; this Windows API remains necessary.
                #pragma warning disable SYSLIB0057
                using var signed=X509Certificate.CreateFromSignedFile(path);
                #pragma warning restore SYSLIB0057
                using var certificate=X509CertificateLoader.LoadCertificate(signed.GetRawCertData());
                signer=certificate.GetNameInfo(X509NameType.SimpleName,false);
            }
            catch(CryptographicException) { valid=false; }
        }
        var hash=requireHash?Convert.ToHexString(SHA256.HashData(file)):"";
        return new BinaryIdentity(Path.GetFullPath(path),version.ProductName??"",version.CompanyName??"",version.OriginalFilename??"",signer,valid,hash,file.Length,trust);
    }

    private static int VerifyTrust(string path,bool cacheOnly)
    {
        var file=new TrustFile { Size=(uint)Marshal.SizeOf<TrustFile>(), Path=path };
        var pointer=Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        Marshal.StructureToPtr(file,pointer,false);
        var data=new TrustData { Size=(uint)Marshal.SizeOf<TrustData>(),UIChoice=2,UnionChoice=1,File=pointer,
            StateAction=1,ProviderFlags=cacheOnly?0x1000u:0u };
        var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        try { return WinVerifyTrust(new IntPtr(-1),ref action,ref data); }
        finally { data.StateAction=2; WinVerifyTrust(new IntPtr(-1),ref action,ref data); Marshal.DestroyStructure<TrustFile>(pointer);Marshal.FreeHGlobal(pointer); }
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct TrustFile { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Handle,Subject; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData { public uint Size; public IntPtr PolicyCallback,SipClient; public uint UIChoice,RevocationChecks,UnionChoice; public IntPtr File; public uint StateAction; public IntPtr State,Url; public uint ProviderFlags,UIContext; }
    [DllImport("wintrust.dll",ExactSpelling=true)] private static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
}
