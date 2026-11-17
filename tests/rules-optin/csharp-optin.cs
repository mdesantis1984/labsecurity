// Fixtures for rules/optin/csharp-optin.yaml. Nothing here is compiled or executed.
class Endpoints
{
    void Map(WebApplication app, CorsPolicyBuilder builder)
    {
        // ruleid: labsec.csharp.antiforgery-disabled
        app.MapPost("/hook", () => Results.Ok()).DisableAntiforgery();
        // ok: labsec.csharp.antiforgery-disabled
        app.MapPost("/form", () => Results.Ok());

        // ruleid: labsec.csharp.cors-allow-any-origin
        builder.AllowAnyOrigin().AllowAnyMethod();
        // ok: labsec.csharp.cors-allow-any-origin
        builder.WithOrigins("https://app.example.test").AllowAnyMethod();
    }
}

class WebhookController : Controller
{
    // ruleid: labsec.csharp.antiforgery-disabled
    [IgnoreAntiforgeryToken]
    public IActionResult Receive() { return Ok(); }

    // ok: labsec.csharp.antiforgery-disabled
    [ValidateAntiForgeryToken]
    public IActionResult Save() { return Ok(); }
}
