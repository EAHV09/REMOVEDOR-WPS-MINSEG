namespace Minseg.Core;

/// <summary>Resolves only the explicitly launched file, never a shell command or registry switches.</summary>
public static class RegisteredUninstaller
{
    public static void RequireIdentity(BinaryIdentity identity,Product product)
    {
        if(!identity.SignatureValid)
            throw new IOException($"Windows no validó la firma del desinstalador (código {(identity.TrustStatus is int code?$"0x{code:X8}":"no disponible")}). Archivo: {identity.Path}. Firmante: {identity.Signer}. Comprueba fecha, certificados y conexión del equipo.");
        if(SafetyRules.Identify(identity)!=product)
            throw new IOException($"El archivo tiene firma válida, pero su fabricante o producto no coincide con {product.Display()}. Firmante: {identity.Signer}. Producto: {identity.ProductName}. Archivo: {identity.Path}.");
    }
    public static string Resolve(string command)
    {
        var text=Environment.ExpandEnvironmentVariables(command.Trim());
        if(text.Length==0)throw new IOException("La entrada de instalación no tiene un desinstalador. Revisa Aplicaciones de Windows.");
        string? path=null;
        if(text.StartsWith('"'))path=PathSafety.ExecutableFromCommand(text);
        else
        {
            // Unlike a service command line, ProcessRunner supplies this complete path as FileName.
            // Do not guess if more than one .exe boundary can represent the registered executable.
            var candidates=new List<string>();
            for(int at=0;at<=text.Length-4;at++)
                if(text.AsSpan(at,4).Equals(".exe",StringComparison.OrdinalIgnoreCase)
                    &&(at+4==text.Length||char.IsWhiteSpace(text[at+4])))
                    candidates.Add(text[..(at+4)]);
            if(candidates.Count==1)path=candidates[0];
        }
        if(path==null||!SafetyRules.IsLocalPath(path)||path.Contains('"')||path.Contains('%')
            ||!Path.GetExtension(path).Equals(".exe",StringComparison.OrdinalIgnoreCase))
            throw new IOException("La ruta del desinstalador está incompleta o es ambigua. No se ejecutó. Revisa la entrada en Aplicaciones de Windows.");
        return Path.GetFullPath(path);
    }
}
