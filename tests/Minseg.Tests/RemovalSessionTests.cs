using Minseg.Core;
using Xunit;
namespace Minseg.Tests;

public class RemovalSessionTests
{
    [Fact]
    public void A_second_action_remains_blocked_until_the_original_process_finishes()
    {
        var pending=new TaskCompletionSource<ProcessResult>();var session=new RemovalSession();
        session.Observe(Product.Wps,new(null,"","",true,pending.Task));
        Assert.NotNull(session.PendingReason(Product.Wps));Assert.NotNull(session.PendingReason(Product.Wps));
        Assert.Null(session.PendingReason(Product.AnyDesk));
        pending.SetResult(new(0,"","",false));Assert.Null(session.PendingReason(Product.Wps));
    }
    [Fact]
    public void Restart_or_failed_completion_is_not_forgotten_on_the_next_action()
    {
        var session=new RemovalSession();session.Observe(Product.AnyDesk,new(3010,"","",false));
        Assert.Contains("reinicio",session.PendingReason(Product.AnyDesk));Assert.NotNull(session.PendingReason(Product.AnyDesk));
        var pending=new TaskCompletionSource<ProcessResult>();session.Observe(Product.Wps,new(null,"","",true,pending.Task));
        pending.SetResult(new(1,"","",false));Assert.NotNull(session.PendingReason(Product.Wps));Assert.NotNull(session.PendingReason(Product.Wps));
    }
    [Fact]
    public void A_second_click_cannot_bypass_the_running_user_uninstaller_by_elevating()
    {
        var selected=new HashSet<Product>{Product.AnyDesk};var session=new RemovalSession();
        var inventory=new ScanResult(DateTimeOffset.Now,[],[new(Product.AnyDesk,"AnyDesk","1","AnyDesk","key","","",true)],[],true);
        Assert.True(RemovalLaunch.NeedsElevation(false,inventory,null,selected,session));
        var pending=new TaskCompletionSource<ProcessResult>();session.Observe(Product.AnyDesk,new(null,"","",true,pending.Task));
        Assert.False(RemovalLaunch.NeedsElevation(false,inventory,null,selected,session));
        pending.SetResult(new(0,"","",false));Assert.True(RemovalLaunch.NeedsElevation(false,inventory,null,selected,session));
    }
    [Fact]
    public void An_incomplete_Uac_worker_blocks_another_worker_and_cleanup_in_the_parent_window()
    {
        var selected=new HashSet<Product>{Product.Wps};var parent=new RemovalSession();
        var inventory=new ScanResult(DateTimeOffset.Now,[],[new(Product.Wps,"WPS","1","Kingsoft","key","","",true)],[],true);
        Assert.True(RemovalLaunch.NeedsElevation(false,inventory,null,selected,parent));
        parent.RecordMachineContinuation(selected,2);
        Assert.False(RemovalLaunch.NeedsElevation(false,inventory,null,selected,parent));
        Assert.True(parent.HasPending(selected));Assert.NotNull(parent.PendingReason(Product.Wps));
    }
}
