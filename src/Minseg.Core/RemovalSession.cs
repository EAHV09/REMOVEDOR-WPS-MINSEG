namespace Minseg.Core;

// Shared by uninstall and manual/automatic cleanup for the entire window lifetime.
public sealed class RemovalSession
{
    private readonly Dictionary<Product,Task<ProcessResult>> running=[];
    private readonly Dictionary<Product,string> pending=[];
    public void RecordMachineContinuation(IReadOnlySet<Product> selected,int exitCode)
    {
        if(exitCode==0)return;
        foreach(var product in selected)pending[product]="La continuación como administrador no confirmó que terminó. Revisa su informe antes de otra acción; no se repetirá en esta ventana.";
    }
    public bool HasPending(IEnumerable<Product> selected)=>selected.Any(p=>PendingReason(p)!=null);
    public void Observe(Product product,ProcessResult result)
    {
        if(result.TimedOut)
        {
            if(result.Completion!=null)running[product]=result.Completion;
            else pending[product]="No se pudo comprobar si terminó el desinstalador. Revisión pendiente.";
        }
        else if(result.ExitCode==3010)pending[product]="El desinstalador necesita un reinicio. No se repetirá ni se limpiarán sus archivos en esta sesión.";
    }
    public string? PendingReason(Product product)
    {
        if(running.TryGetValue(product,out var completion))
        {
            if(!completion.IsCompleted)return "El desinstalador anterior sigue abierto. Complétalo antes de volver a actuar.";
            running.Remove(product);
            try
            {
                var result=completion.GetAwaiter().GetResult();Observe(product,result);
                if(result.ExitCode is not (0 or 3010))pending[product]="El desinstalador anterior terminó con error. Revisa su resultado antes de otra acción.";
            }
            catch{pending[product]="No se pudo comprobar el resultado del desinstalador anterior.";}
        }
        return pending.GetValueOrDefault(product);
    }
}
