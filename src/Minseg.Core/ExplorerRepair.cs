using Microsoft.Win32;
namespace Minseg.Core;
internal sealed record ExplorerEdit(bool Classes,string Key,string Name,string Expected,string? Replacement);
internal interface IExplorerTree
{
    string? Read(string key,string name="");
    string[] Names(string key);
    string[] Children(string key);
}
internal static class ExplorerRepair
{
    internal const string Preview="{8895b1c6-b41f-4c1c-a562-0d564250836f}";
    internal const string PreviewList=@"Software\Microsoft\Windows\CurrentVersion\PreviewHandlers";
    internal const string FileExts=@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";
    internal static IReadOnlyList<ExplorerEdit> Plan(IExplorerTree classes,IExplorerTree settings,IExplorerTree machineClasses,
        Func<string,bool> wps,Func<string,bool> microsoft,IReadOnlyList<OfficeAssociation> office,Func<bool> more)
    {
        var edits=new List<ExplorerEdit>();
        var ids=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var previews=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var executables=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool WpsCommand(string? command)
        {
            var path=PathSafety.ExecutableFromCommand(command??"");
            if(path==null||!wps(path))return false;
            executables.Add(Path.GetFileName(path));return true;
        }
        var identifiers=OfficeAssociationRules.Apps.Values.SelectMany(a=>a.Extensions).Concat(new[]{".pdf",".wps",".wpt",".et",".ett",".dps",".dpt"}).Where(x=>x.StartsWith('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var trees=new[]{classes,machineClasses}.Distinct().ToArray();
        foreach(var tree in trees)
        {
            foreach(var id in tree.Children("").Where(id=>System.Text.RegularExpressions.Regex.IsMatch(id,@"^(WPS|WPSOffice|Kingsoft|Kso|ET|WPP)\.[a-z0-9_.-]+$",System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
            {
                if(!more())return edits;
                if(WpsCommand(tree.Read(id+@"\shell\open\command")))ids.Add(id);
            }
        }
        // Inspect only preview CLSIDs referenced by relevant file types or PreviewHandlers.
        // Enumerating every COM class twice exhausted the scan budget before any repairs.
        var previewIds=new HashSet<string>(settings.Names(PreviewList),StringComparer.OrdinalIgnoreCase);
        foreach(var tree in trees)
            foreach(var key in identifiers.Concat(identifiers.Select(e=>"SystemFileAssociations\\"+e)).Concat(ids).Concat(office.Select(a=>a.ProgId)))
            {
                if(!more())return edits;
                var id=tree.Read(key+@"\shellex\"+Preview);
                if(id!=null)previewIds.Add(id);
            }
        foreach(var tree in trees)
            foreach(var id in previewIds.Where(id=>Guid.TryParseExact(id,"B",out _)))
            {
                if(!more())return edits;
                var dll=Dll(tree.Read(@"CLSID\"+id+@"\InprocServer32"));
                if(dll!=null&&wps(dll))previews.Add(id);
            }
        void Edit(bool cls,string key,string name,string? expected,string? replacement)
        {
            if(expected!=null&&expected!=replacement)edits.Add(new(cls,key,name,expected,replacement));
        }
        string? OfficePreview(string progId)
        {
            var id=machineClasses.Read(progId+@"\shellex\"+Preview);
            if(id==null||!Guid.TryParseExact(id,"B",out _))return null;
            var dll=Dll(machineClasses.Read(@"CLSID\"+id+@"\InprocServer32"));
            return dll!=null&&microsoft(dll)?id:null;
        }
        foreach(var extension in identifiers)
        {
            if(!more())return edits;
            var association=office.SingleOrDefault(a=>a.Identifier.Equals(extension,StringComparison.OrdinalIgnoreCase));
            var registered=classes.Read(extension);
            // Unregister a WPS fallback only; UserChoice is never read for writing or deleted.
            if(registered!=null&&ids.Contains(registered))Edit(true,extension,"",registered,null);
            foreach(var key in new[]{extension,registered,association?.ProgId,"SystemFileAssociations\\"+extension}.Where(s=>!string.IsNullOrEmpty(s)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var previewKey=key+@"\shellex\"+Preview;var current=classes.Read(previewKey);
                if(current!=null&&previews.Contains(current))Edit(true,previewKey,"",current,association==null?null:OfficePreview(association.ProgId));
            }
            foreach(var (cls,key) in new[]{(true,extension+@"\OpenWithProgids"),(false,FileExts+"\\"+extension+@"\OpenWithProgids")})
                foreach(var id in (cls?classes:settings).Names(key).Where(ids.Contains))Edit(cls,key,id,(cls?classes:settings).Read(key,id),null);
            var list=FileExts+"\\"+extension+@"\OpenWithList";
            var removed=settings.Names(list).Where(n=>n.Length==1).Select(n=>(Name:n,Value:settings.Read(list,n))).Where(v=>executables.Contains(v.Value??"")).ToArray();
            var mru=settings.Read(list,"MRUList");
            if(mru!=null&&removed.Length>0)Edit(false,list,"MRUList",mru,string.Concat(mru.Where(c=>!removed.Any(v=>v.Name==c.ToString()))));
            foreach(var letter in removed)Edit(false,list,letter.Name,letter.Value,null);
        }
        foreach(var key in ids.Concat(office.Select(a=>a.ProgId)).Concat(executables.Select(e=>"Applications\\"+e)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if(!more())return edits;
            foreach(var verb in new[]{"open","edit"})
            {
                var commandKey=key+"\\shell\\"+verb+"\\command";
                var currentCommand=classes.Read(commandKey);
                if(!WpsCommand(currentCommand))continue;
                var original=machineClasses.Read(commandKey);var exe=PathSafety.ExecutableFromCommand(original??"");
                bool officeClass=office.Any(a=>a.ProgId.Equals(key,StringComparison.OrdinalIgnoreCase));
                Edit(true,commandKey,"",currentCommand,officeClass&&exe!=null&&microsoft(exe)?original:null);
            }
        }
        foreach(var id in settings.Names(PreviewList).Where(previews.Contains))Edit(false,PreviewList,id,settings.Read(PreviewList,id),null);
        return edits.DistinctBy(e=>(e.Classes,e.Key,e.Name)).ToArray();
    }
    internal static string? Dll(string? raw)
    {
        var path=Environment.ExpandEnvironmentVariables(raw??"").Trim().Trim('"');
        return SafetyRules.IsLocalPath(path)&&Path.GetExtension(path).Equals(".dll",StringComparison.OrdinalIgnoreCase)?path:null;
    }
}
