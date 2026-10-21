using Minseg.Core;
using Xunit;
namespace Minseg.Tests;
public class PolicyStatusTests
{
    [Fact]
    public void Older_loaded_audit_policy_is_not_reported_as_active_blocking()
    {
        var json="{\"Policies\":[{\"PolicyID\":\""+PolicyBuilder.PolicyId+"\",\"IsEnforced\":true,\"Version\":\"281474976710656\"}]}";
        Assert.Equal("Reinicio pendiente",PolicyStatus.Parse(json,false,"1.0.1.0").Status);
        Assert.Equal("En auditoría",PolicyStatus.Parse(json,true,"1.0.0.0").Status);
    }
    [Fact]
    public void Matching_enforced_version_is_reported_active()
    {
        var json="{\"Policies\":[{\"PolicyID\":\""+PolicyBuilder.PolicyId+"\",\"IsEnforced\":true,\"Version\":281474976710656}]}";
        Assert.Equal("Bloqueo activo",PolicyStatus.Parse(json,false,"1.0.0.0").Status);
    }
    [Theory]
    [InlineData("{\"Policies\":[]}")]
    [InlineData("{\"Policies\":[{\"PolicyID\":\"{2AD8D02D-A472-4E73-AFC0-50B1DB5208A8}\",\"IsEnforced\":true}]}")]
    public void Missing_version_or_policy_never_reports_active(string json)
        =>Assert.NotEqual("Bloqueo activo",PolicyStatus.Parse(json,false,"1.0.0.0").Status);
    [Fact]
    public void Audit_must_be_loaded_before_enforcement()
    {
        Assert.Throws<InvalidOperationException>(()=>PolicyStatus.RequireAudit(new("Reinicio pendiente","",true),true));
        Assert.Throws<InvalidOperationException>(()=>PolicyStatus.RequireAudit(new("En auditoría","",true),false));
        PolicyStatus.RequireAudit(new("En auditoría","",true),true);
    }
}
