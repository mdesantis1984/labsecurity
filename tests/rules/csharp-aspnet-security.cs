// Fixtures for rules/opengrep/csharp-aspnet-security.yaml. Nothing here is compiled or executed.
class JwtSetup
{
    void Configure(JwtBearerOptions options, IHostEnvironment env)
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // ruleid: labsec.csharp.jwt-validate-issuer-disabled
            ValidateIssuer = false,
            // ruleid: labsec.csharp.jwt-validate-audience-disabled
            ValidateAudience = false,
            // ruleid: labsec.csharp.jwt-signature-validation-disabled
            ValidateIssuerSigningKey = false,
        };

        // ruleid: labsec.csharp.jwt-signature-validation-disabled
        options.TokenValidationParameters.RequireSignedTokens = false;

        // ruleid: labsec.csharp.jwt-require-https-metadata-disabled
        options.RequireHttpsMetadata = false;

        if (env.IsDevelopment())
        {
            // ok: labsec.csharp.jwt-require-https-metadata-disabled
            options.RequireHttpsMetadata = false;
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // ok: labsec.csharp.jwt-validate-issuer-disabled
            ValidateIssuer = true,
            // ok: labsec.csharp.jwt-validate-audience-disabled
            ValidateAudience = true,
            // ok: labsec.csharp.jwt-signature-validation-disabled
            ValidateIssuerSigningKey = true,
            // ok: labsec.csharp.jwt-signature-validation-disabled
            RequireSignedTokens = true,
        };
        // ok: labsec.csharp.jwt-require-https-metadata-disabled
        options.RequireHttpsMetadata = true;
    }
}

class CorsSetup
{
    void Configure(CorsPolicyBuilder builder)
    {
        // ruleid: labsec.csharp.cors-reflect-any-origin-with-credentials
        builder.SetIsOriginAllowed(origin => true).AllowCredentials();

        // ok: labsec.csharp.cors-reflect-any-origin-with-credentials
        builder.WithOrigins("https://app.example.test").AllowCredentials();

        // ok: labsec.csharp.cors-reflect-any-origin-with-credentials
        builder.SetIsOriginAllowed(origin => origin.EndsWith(".example.test")).AllowCredentials();
    }
}

class CookieSetup
{
    void Configure(HttpResponse response, CookieAuthenticationOptions o)
    {
        // ruleid: labsec.csharp.cookie-secure-disabled
        response.Cookies.Append("sid", "x", new CookieOptions { Secure = false });
        // ruleid: labsec.csharp.cookie-secure-disabled
        o.Cookie.SecurePolicy = CookieSecurePolicy.None;
        // ruleid: labsec.csharp.cookie-httponly-disabled
        response.Cookies.Append("sid", "x", new CookieOptions { HttpOnly = false });
        // ruleid: labsec.csharp.cookie-httponly-disabled
        o.Cookie.HttpOnly = false;

        // ok: labsec.csharp.cookie-secure-disabled
        response.Cookies.Append("sid", "x", new CookieOptions { Secure = true, HttpOnly = true });
        // ok: labsec.csharp.cookie-secure-disabled
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        // ok: labsec.csharp.cookie-httponly-disabled
        o.Cookie.HttpOnly = true;
    }
}

class TlsSetup
{
    void Configure(HttpClientHandler handler, SocketsHttpHandler sockets)
    {
        // ruleid: labsec.csharp.tls-certificate-validation-bypass
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        // ruleid: labsec.csharp.tls-certificate-validation-bypass
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        // ruleid: labsec.csharp.tls-certificate-validation-bypass
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;

        // ok: labsec.csharp.tls-certificate-validation-bypass
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => errors == SslPolicyErrors.None;
    }
}

class Pipeline
{
    void Configure(WebApplication app)
    {
        // ruleid: labsec.csharp.developer-exception-page-unguarded
        app.UseDeveloperExceptionPage();

        if (app.Environment.IsDevelopment())
        {
            // ok: labsec.csharp.developer-exception-page-unguarded
            app.UseDeveloperExceptionPage();
        }
        else
        {
            // ok: labsec.csharp.developer-exception-page-unguarded
            app.UseExceptionHandler("/error");
        }
    }
}

class CorsWithoutCredentials
{
    void Configure(CorsPolicyBuilder builder)
    {
        // ok: labsec.csharp.cors-reflect-any-origin-with-credentials
        builder.SetIsOriginAllowed(origin => true).AllowAnyMethod();
    }
}
