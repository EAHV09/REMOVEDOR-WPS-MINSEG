namespace Minseg.Core;

// These records live in the administrator-writable registry, not in user input or launch arguments.
internal sealed record OfficeFileState(string? CurrentHash,string? PendingHash)
{
    internal bool Accepts(string hash)=>hash==CurrentHash||hash==PendingHash;
}
internal sealed record OfficePolicyFile(string Path,string Hash);
internal sealed record OfficePolicyState(OfficePolicyFile? Current,OfficePolicyFile? Pending)
{
    internal OfficePolicyFile? Find(string? path)=>
        path!=null&&Current?.Path.Equals(path,StringComparison.OrdinalIgnoreCase)==true?Current:
        path!=null&&Pending?.Path.Equals(path,StringComparison.OrdinalIgnoreCase)==true?Pending:null;
    internal static void Publish(OfficePolicyState before,OfficePolicyFile next,string? expected,
        Func<string?> readPointer,Action<string> writePointer,Action<OfficePolicyState> persist)
    {
        if(!string.Equals(readPointer(),expected,StringComparison.OrdinalIgnoreCase))throw new IOException("La política cambió. Se conserva.");
        // Keep both possible pointers recognizable until the publication is complete, including after a crash.
        persist(new(before.Find(expected),next));
        if(!string.Equals(readPointer(),expected,StringComparison.OrdinalIgnoreCase))throw new IOException("La política cambió. Se conserva.");
        writePointer(next.Path);
        if(!string.Equals(readPointer(),next.Path,StringComparison.OrdinalIgnoreCase))throw new IOException("Windows no confirmó la política.");
        persist(new(next,null));
    }
}
