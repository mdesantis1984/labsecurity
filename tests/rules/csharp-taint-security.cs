// Fixtures for rules/opengrep/csharp-taint-security.yaml. Nothing here is compiled or executed.
class LogController : Controller
{
    private readonly ILogger<LogController> _logger;

    public IActionResult Login(string user)
    {
        // ruleid: labsec.csharp.log-injection
        _logger.LogInformation($"Login attempt for {user}");
        return Ok();
    }

    public IActionResult Search()
    {
        var term = Request.Query["q"];
        // ruleid: labsec.csharp.log-injection
        _logger.LogWarning("Search for " + term);
        return Ok();
    }

    public IActionResult Safe(string user)
    {
        // ok: labsec.csharp.log-injection
        _logger.LogInformation("Login attempt for {User}", user);
        var clean = user.Replace("\n", "").Replace("\r", "");
        // ok: labsec.csharp.log-injection
        _logger.LogInformation($"Login attempt for {clean}");
        // ok: labsec.csharp.log-injection
        _logger.LogInformation($"Started at {DateTime.UtcNow}");
        return Ok();
    }
}

class PluginController : Controller
{
    public IActionResult Load(string typeName)
    {
        // ruleid: labsec.csharp.unsafe-reflection-tainted-type
        var type = Type.GetType(typeName);
        return Ok(type);
    }

    public IActionResult LoadAssembly()
    {
        var name = Request.Query["asm"];
        // ruleid: labsec.csharp.unsafe-reflection-tainted-type
        Assembly.LoadFrom(name);
        return Ok();
    }

    public IActionResult Fixed()
    {
        // ok: labsec.csharp.unsafe-reflection-tainted-type
        var type = Type.GetType("MyApp.Plugins.Default");
        return Ok(type);
    }
}
