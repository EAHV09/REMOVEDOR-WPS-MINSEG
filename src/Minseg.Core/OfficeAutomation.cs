namespace Minseg.Core;

public enum OfficeCommand{None,Prepare,Invalid}
public sealed record OfficePreparation(string Path,bool AppliesAtSignIn,string Message)
{
    public int ExitCode=>AppliesAtSignIn?0:10;
}
public static class OfficeAutomation
{
    public static string WorkerFeedback(OfficePlan plan,bool preparedMatches)=>!preparedMatches?
        "Office sigue pendiente: no se comprobó una preparación completa para lo instalado. Revisa el informe de administrador o pulsa Preparar Office automático.":
        plan.Summary+". XML de esta PC preparado. "+OfficeRecovery.PolicyExplanation(plan.PolicyState);
    public static OfficeCommand Parse(IEnumerable<string> arguments)
    {
        var args=arguments.ToArray();
        if(args.SequenceEqual(new[]{"--prepare-office"}))return OfficeCommand.Prepare;
        return args.Any(a=>a.StartsWith("--prepare-office",StringComparison.OrdinalIgnoreCase))?OfficeCommand.Invalid:OfficeCommand.None;
    }
    internal static string PolicyState(bool domain,bool admin,string? policyPath,bool mdm,bool ownsPolicy,bool targetsPreparedFile,bool preparedFileVerified)
    {
        if(mdm)return "Managed";
        if(domain&&targetsPreparedFile)return preparedFileVerified?"GpoPending":"GpoReady";
        if(domain&&ownsPolicy)return "Pending";
        return OfficeAssociationRules.Mode(domain,admin,policyPath,false);
    }
    internal static void RequireComplete(OfficePlan plan)
    {
        if(!plan.DetectionComplete)throw new InvalidOperationException("La detección de Office fue parcial. Revisa los avisos antes de programar sus predeterminados; se conserva la configuración anterior.");
        if(plan.Associations.Count==0)throw new InvalidOperationException("No se encontraron formatos de Office verificados para preparar.");
        if(!OfficePolicy.CanPrepare(plan.PolicyState))throw new InvalidOperationException(OfficeRecovery.PolicyExplanation(plan.PolicyState));
    }
}
