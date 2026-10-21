using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace Minseg.Core;
internal static class PersistenceSnapshot
{
    public static string Hash(string text)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    public static string Service(RegistryKey key)=>JsonSerializer.Serialize(ReadTree(key,0));
    private static object ReadTree(RegistryKey key,int depth)
    {
        if(depth>8)throw new IOException("Servicio con configuración compleja. Se conserva.");
        var values=key.GetValueNames().Order(StringComparer.Ordinal).Select(n=>new{Name=n,Kind=key.GetValueKind(n).ToString(),Value=key.GetValue(n,null,RegistryValueOptions.DoNotExpandEnvironmentNames)}).ToArray();
        var children=new SortedDictionary<string,object>(StringComparer.Ordinal);
        foreach(var name in key.GetSubKeyNames().Order(StringComparer.Ordinal)){using var child=key.OpenSubKey(name)!;children[name]=ReadTree(child,depth+1);}
        return new{Key=key.Name,Values=values,Children=children};
    }
}
