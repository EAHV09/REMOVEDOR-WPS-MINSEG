using System.Diagnostics;
namespace Minseg.Core;

public sealed record ProcessResult(int? ExitCode,string Output,string Error,bool TimedOut,Task<ProcessResult>? Completion=null);
public static class ProcessRunner
{
    public static async Task<ProcessResult> RunAsync(CommandSpec command,TimeSpan timeout,bool capture=true,Action? started=null)
    {
        if(!SafetyRules.IsLocalPath(command.Executable))throw new IOException("Ejecutable no válido.");
        PathSafety.RequireNoReparse(command.Executable);
        var info=new ProcessStartInfo(command.Executable){UseShellExecute=false,CreateNoWindow=capture,RedirectStandardOutput=capture,RedirectStandardError=capture,
            WorkingDirectory=Path.GetDirectoryName(command.Executable)!};
        foreach(var argument in command.Arguments)info.ArgumentList.Add(argument); // ASVS 1.2.5, no cmd.exe or string-built shell.
        if(Path.GetFileName(command.Executable).Equals("powershell.exe",StringComparison.OrdinalIgnoreCase))
            info.Environment["PSModulePath"]=Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\Modules");
        var process=Process.Start(info)??throw new IOException("Windows no pudo abrir la herramienta.");
        started?.Invoke();
        var stdout=capture?process.StandardOutput.ReadToEndAsync():Task.FromResult("");
        var stderr=capture?process.StandardError.ReadToEndAsync():Task.FromResult("");
        async Task<ProcessResult> Complete()
        {
            try{await process.WaitForExitAsync();return new(process.ExitCode,await stdout,await stderr,false);}
            finally{process.Dispose();}
        }
        var completion=Complete();
        try{return await completion.WaitAsync(timeout);}
        catch(TimeoutException){return new(null,"","La operación sigue abierta. No se cerró por la fuerza.",true,completion);}
    }
}
