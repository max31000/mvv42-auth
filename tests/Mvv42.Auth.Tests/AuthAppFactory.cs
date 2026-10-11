using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Mvv42.Auth.Tests;

public class AuthAppFactory : WebApplicationFactory<Program>
{
    private readonly TempDir _keys = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Auth:KeysPath", _keys.Path);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _keys.Dispose();
    }
}
