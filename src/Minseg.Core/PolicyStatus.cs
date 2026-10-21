using System.Text.Json;
namespace Minseg.Core;
public static class PolicyStatus
{
    public static PolicyState Parse(string json,bool audit,string version)
    {
        using var doc=JsonDocument.Parse(json);
        if(!doc.RootElement.TryGetProperty("Policies",out var policies)||policies.ValueKind!=JsonValueKind.Array)
            return new("No comprobado","Windows devolvió un formato de estado distinto.",audit);
        foreach(var policy in policies.EnumerateArray())
        {
            if(!policy.TryGetProperty("PolicyID",out var id)||!Guid.TryParse(id.ToString(),out var parsed)||parsed!=Guid.Parse(PolicyBuilder.PolicyId))continue;
            bool loaded=policy.TryGetProperty("IsEnforced",out var active)&&bool.TryParse(active.ToString(),out var enforced)&&enforced;
            bool same=policy.TryGetProperty("Version",out var v)&&ulong.TryParse(v.ToString(),out var packed)&&packed==PackVersion(version);
            return loaded&&same?new(audit?"En auditoría":"Bloqueo activo","Windows confirmó esta versión. Cubre productos y muestras conocidas; las variantes nuevas requieren revisión.",audit)
                :new("Reinicio pendiente","Windows aún no confirmó la carga de esta versión. Vuelve a comprobar después de reiniciar.",audit);
        }
        return new("Reinicio pendiente","Windows todavía no informa que esta política esté cargada.",audit);
    }
    public static ulong PackVersion(string version)
    {
        if(string.IsNullOrEmpty(version))throw new IOException("Falta la versión de la política. Vuelve a aplicar la prueba.");
        var parts=version.Split('.');if(parts.Length!=4)throw new IOException("Versión de política inválida.");
        ulong value=0;foreach(var part in parts){if(!ushort.TryParse(part,out var n))throw new IOException("Versión de política inválida.");value=(value<<16)|n;}return value;
    }
    public static void RequireAudit(PolicyState state,bool checkedCompatibility)
    {
        if(!checkedCompatibility||state.Audit!=true||state.Status!="En auditoría")
            throw new InvalidOperationException("Primero carga la prueba en auditoría, comprueba su estado y confirma que tus otros programas funcionan.");
    }
}
