namespace Minseg.Core;

public static class ErrorDetails
{
    public static string Message(Exception error)
    {
        for(Exception? current=error;current!=null;current=current.InnerException)
            if(!string.IsNullOrWhiteSpace(current.Message))return current.Message.Trim();
        return $"Windows no devolvió una explicación. Código: 0x{error.HResult:X8} ({error.GetType().Name}). Guarda el detalle para revisarlo.";
    }

    public static string Diagnostic(Exception error,string operation)
        =>$"MINSEG Control · {DateTimeOffset.Now:O}\nPaso: {operation}\nTipo: {error.GetType().FullName}\nCódigo: 0x{error.HResult:X8}\n{Message(error)}\n\n{error}";
}
