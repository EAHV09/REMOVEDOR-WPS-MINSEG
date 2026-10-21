using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public class RemovalWorkflowTests
{
    private static readonly BinaryIdentity Identity=new(@"C:\Apps\AnyDesk\AnyDesk.exe","AnyDesk","AnyDesk","AnyDesk.exe","AnyDesk Software GmbH",true,new string('A',64),100);
    private static Finding Binary(Product product=Product.AnyDesk,Trust trust=Trust.Confirmed,FindingKind kind=FindingKind.Binary)
        =>new(product,kind,"file",Identity.Path,trust,"",Identity);
    private static ScanResult Scan(params Finding[] findings)=>new(DateTimeOffset.Now,findings,[],[],true);
    private sealed class Fake:IRemovalSteps
    {
        public readonly List<string> Calls=[];
        public readonly Queue<ScanResult> Scans=new();
        public ScanResult Inventory=Scan();
        public IReadOnlySet<Product> Blocked=new HashSet<Product>();
        public IReadOnlyList<Finding> Cleaned=[];
        public IReadOnlySet<Product> CleanupBlocked=new HashSet<Product>();
        public IReadOnlySet<Product> NeedsElevation=new HashSet<Product>();
        public readonly List<ScanResult?> History=[];
        public Task<ScanResult> PrepareAsync(IReadOnlySet<Product> selected,CancellationToken token)
        {token.ThrowIfCancellationRequested();Calls.Add("prepare");return Task.FromResult(Scans.Dequeue());}
        public Task<ScanResult> ScanAsync(ScanResult? previous,CancellationToken token)
        {token.ThrowIfCancellationRequested();Calls.Add("scan");History.Add(previous);return Task.FromResult(Scans.Dequeue());}
        public Task<IReadOnlySet<Product>> UninstallAsync(ScanResult before,IReadOnlySet<Product> selected)
        {Calls.Add("uninstall");return Task.FromResult(Blocked);}
        public Task<ScanResult> ReadInventoryAsync(){Calls.Add("inventory");return Task.FromResult(Inventory);}
        public Task<CleanupResult> CleanAsync(ScanResult scan,IReadOnlyList<Finding> chosen){Calls.Add("clean");Cleaned=chosen;return Task.FromResult(new CleanupResult(CleanupBlocked,NeedsElevation));}
    }
    [Fact]
    public async Task Empty_directories_can_be_cleaned_without_binary_identity_but_unchanged_results_do_not_loop()
    {
        var directory=new Finding(Product.Wps,FindingKind.Directory,"WPS",@"C:\ProgramData\WPS",Trust.Confirmed,"",Reference:@"C:\ProgramData\WPS");
        var f=new Fake();f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(directory));f.Scans.Enqueue(Scan(directory));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.Wps},CancellationToken.None);
        Assert.Same(directory,Assert.Single(f.Cleaned));Assert.Single(f.Calls,c=>c=="clean");
        Assert.False(result.VerifiedClear(Product.Wps));
    }
    [Fact]
    public async Task Personal_and_cloud_data_do_not_get_selected_for_automatic_cleanup()
    {
        var personal=new Finding(Product.Wps,FindingKind.PersonalData,"WPSDrive",@"C:\Users\test\Documents\WPSDrive",Trust.Protected,"");
        var f=new Fake();f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(personal));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.Wps},CancellationToken.None);
        Assert.Empty(f.Cleaned);Assert.True(result.VerifiedClear(Product.Wps));Assert.Contains(personal,result.Scan.Findings);
    }
    [Fact]
    public async Task One_action_scans_uninstalls_cleans_and_verifies_only_selected_product()
    {
        var f=new Fake();f.Scans.Enqueue(Scan(Binary()));f.Scans.Enqueue(Scan(Binary(),Binary(Product.Wps),Binary(trust:Trust.Review),Binary(kind:FindingKind.PersonalData)));f.Scans.Enqueue(Scan());
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.Single(f.Cleaned);Assert.Equal(Product.AnyDesk,f.Cleaned[0].Product);
        Assert.Equal(new[]{"prepare","uninstall","inventory","scan","inventory","clean","scan","inventory"},f.Calls);
        Assert.True(result.VerifiedClear(Product.AnyDesk));
    }
    [Fact]
    public async Task An_unfinished_uninstaller_blocks_cleanup_even_when_its_registry_key_disappears()
    {
        var f=new Fake{Blocked=new HashSet<Product>{Product.AnyDesk}};f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(Binary()));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.Empty(f.Cleaned);Assert.False(result.VerifiedClear(Product.AnyDesk));
        Assert.DoesNotContain("scan",f.Calls);
    }
    [Fact]
    public async Task Incomplete_registry_does_not_authorize_automatic_cleanup()
    {
        var f=new Fake{Inventory=Scan() with{Complete=false,Warnings=["Registro no accesible"]}};f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(Binary()));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.Empty(f.Cleaned);Assert.False(result.VerifiedClear(Product.AnyDesk));
    }
    [Fact]
    public async Task Still_installed_product_is_not_cleaned()
    {
        var f=new Fake{Inventory=Scan() with{Installed=[new(Product.AnyDesk,"AnyDesk","1","AnyDesk","key",@"C:\Apps\AnyDesk","",true)]}};
        f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(Binary()));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.Empty(f.Cleaned);Assert.False(result.VerifiedClear(Product.AnyDesk));
    }
    [Fact]
    public async Task Cancelling_before_scan_never_uninstalls()
    {
        var f=new Fake();using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.Wps},cts.Token));
        Assert.DoesNotContain("uninstall",f.Calls);
    }
    [Fact]
    public void Preparing_direct_uninstall_preserves_only_previous_confirmed_residue_evidence_for_revalidation()
    {
        var residue=Binary(kind:FindingKind.Residue) with{ContentHash=new string('A',64)};
        var initial=Scan(residue,Binary(),Binary(trust:Trust.Review,kind:FindingKind.Residue));
        var current=Scan(Binary(kind:FindingKind.Service));
        var history=SystemRemovalSteps.WithPriorResidues(current,initial)!;
        Assert.Equal(2,history.Findings.Count);Assert.Contains(residue,history.Findings);
        Assert.Equal(current.CapturedAt,history.CapturedAt);
    }
    [Fact]
    public void Elevation_arguments_accept_only_known_products()
    {
        Assert.Equal(new[]{Product.Wps},RemovalLaunch.Parse(["--remove-machine","wps"]));
        Assert.Empty(RemovalLaunch.Parse(["--remove-machine",@"C:\untrusted.exe"]));
        Assert.Empty(RemovalLaunch.Parse(["--remove-machine","wps","--extra"]));
        Assert.Throws<ArgumentException>(()=>RemovalLaunch.Argument(new HashSet<Product>{(Product)100}));
    }
    [Fact]
    public async Task A_failed_product_does_not_stop_cleanup_of_the_other_product()
    {
        var f=new Fake{Blocked=new HashSet<Product>{Product.AnyDesk}};
        f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(Binary(Product.Wps),Binary()));f.Scans.Enqueue(Scan(Binary()));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.Wps,Product.AnyDesk},CancellationToken.None);
        Assert.Equal(Product.Wps,Assert.Single(f.Cleaned).Product);
        Assert.True(result.VerifiedClear(Product.Wps));Assert.False(result.VerifiedClear(Product.AnyDesk));
    }
    [Fact]
    public async Task A_cleanup_failure_is_not_reported_as_success_even_if_the_final_scan_is_empty()
    {
        var f=new Fake{CleanupBlocked=new HashSet<Product>{Product.AnyDesk}};
        f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(Binary()));f.Scans.Enqueue(Scan());
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.False(result.VerifiedClear(Product.AnyDesk));
    }
    [Fact]
    public async Task Scan_history_survives_uninstall_and_cleanup_but_a_partial_final_scan_never_means_clear()
    {
        var before=Scan(Binary());var after=Scan(Binary(kind:FindingKind.Startup));
        var f=new Fake();f.Scans.Enqueue(before);f.Scans.Enqueue(after);f.Scans.Enqueue(Scan() with{Complete=false});
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.Same(before,f.History[0]);Assert.Same(after,f.History[1]);
        Assert.False(result.VerifiedClear(Product.AnyDesk));
    }
    [Fact]
    public void Elevation_preserves_user_scope_and_requires_current_machine_evidence()
    {
        var selected=new HashSet<Product>{Product.Wps,Product.AnyDesk};
        var machine=new InstalledApp(Product.Wps,"WPS","1","Kingsoft","machine","","",true);
        var inventory=Scan() with{Installed=[machine]};
        Assert.True(RemovalLaunch.NeedsElevation(false,inventory,null,selected));
        Assert.False(RemovalLaunch.NeedsElevation(true,inventory,null,selected));
        Assert.False(RemovalLaunch.NeedsElevation(false,inventory with{Complete=false},null,selected));
        Assert.False(RemovalLaunch.NeedsElevation(false,inventory with{Installed=[machine,machine with{MachineScope=false}]},null,selected));
        Assert.True(RemovalLaunch.NeedsElevation(false,Scan(),Scan(Binary(kind:FindingKind.Service)),selected));
        Assert.False(RemovalLaunch.NeedsElevation(false,Scan(),Scan(Binary(kind:FindingKind.Service,trust:Trust.Review)),selected));
    }
    [Fact]
    public async Task Machine_residue_requests_elevation_without_becoming_an_uninstaller_failure()
    {
        var f=new Fake{NeedsElevation=new HashSet<Product>{Product.AnyDesk}};
        f.Scans.Enqueue(Scan());f.Scans.Enqueue(Scan(Binary(kind:FindingKind.Service)));f.Scans.Enqueue(Scan(Binary(kind:FindingKind.Service)));
        var result=await new RemovalWorkflow(f).RunAsync(new HashSet<Product>{Product.AnyDesk},CancellationToken.None);
        Assert.Empty(result.Blocked);Assert.Contains(Product.AnyDesk,result.NeedsElevation);Assert.False(result.VerifiedClear(Product.AnyDesk));
        Assert.True(RemovalLaunch.RequiresAdministrator(f.Cleaned.Single()));
    }
}
