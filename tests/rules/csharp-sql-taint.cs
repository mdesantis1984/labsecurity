using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Npgsql;

public class TaintRepo
{
    private readonly AppDbContext ctx;

    // ---- labsec.csharp.sql-raw-built-text-variable ---------------------------------------------

    public void BuiltVariablePositive(string name, NpgsqlConnection conn, NpgsqlCommand cmd)
    {
        var sql1 = $"SELECT * FROM users WHERE name = '{name}'";
        // ruleid: labsec.csharp.sql-raw-built-text-variable, labsec.csharp.sql-raw-tainted-input
        var a = ctx.Users.FromSqlRaw(sql1);

        var sql2 = "SELECT * FROM users WHERE name = '" + name + "'";
        // ruleid: labsec.csharp.sql-raw-built-text-variable, labsec.csharp.sql-raw-tainted-input
        ctx.Database.ExecuteSqlRaw(sql2);

        var sql3 = string.Format("SELECT * FROM users WHERE name = '{0}'", name);
        // ruleid: labsec.csharp.sql-raw-built-text-variable, labsec.csharp.sql-raw-tainted-input
        var b = new NpgsqlCommand(sql3, conn);

        var sql4 = $"SELECT * FROM users WHERE name = '{name}'";
        // ruleid: labsec.csharp.sql-raw-built-text-variable, labsec.csharp.sql-raw-tainted-input
        cmd.CommandText = sql4;

        var sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.Append(name).Append("'");
        // ruleid: labsec.csharp.sql-raw-built-text-variable
        var c = ctx.Users.FromSqlRaw(sb.ToString());
    }

    public void BuiltVariableNegative(string name, NpgsqlConnection conn, NpgsqlCommand cmd)
    {
        var constant = "SELECT * FROM users WHERE name = @name";
        // ok: labsec.csharp.sql-raw-built-text-variable
        var a = new NpgsqlCommand(constant, conn);
        a.Parameters.AddWithValue("name", name);

        var joined = "SELECT * " + "FROM users";
        // ok: labsec.csharp.sql-raw-built-text-variable
        var b = ctx.Users.FromSqlRaw(joined);

        // ok: labsec.csharp.sql-raw-built-text-variable
        cmd.CommandText = constant;

        // ok: labsec.csharp.sql-raw-built-text-variable
        var c = ctx.Users.FromSqlInterpolated($"SELECT * FROM users WHERE name = {name}");

        var label = $"user {name}";
        // ok: labsec.csharp.sql-raw-built-text-variable
        Console.WriteLine(label);
    }

    // ---- labsec.csharp.sql-raw-tainted-input -----------------------------------------------------

    // Request input flows through two methods before it reaches the sink (needs --taint-intrafile).
    public object Handler(HttpRequest request)
    {
        var name = request.Query["name"];
        return Lookup(name);
    }

    private object Lookup(object value)
    {
        return Run(value);
    }

    private object Run(object value)
    {
        // ruleid: labsec.csharp.sql-raw-tainted-input
        return ctx.Users.FromSqlRaw(Compose(value));
    }

    private string Compose(object value)
    {
        return "SELECT * FROM users WHERE name = '" + value + "'";
    }

    // A string parameter is treated as untrusted input.
    public object ByParameter(string name, NpgsqlConnection conn)
    {
        var text = Normalize(name);
        // ruleid: labsec.csharp.sql-raw-tainted-input
        var cmd = new NpgsqlCommand(text, conn);
        return cmd;
    }

    private string Normalize(string raw)
    {
        return raw.Trim();
    }

    // Expression-bodied method: its string parameter is also an untrusted source.
    // ruleid: labsec.csharp.sql-raw-tainted-input
    public object ExpressionBodied(string name) => ctx.Users.FromSqlRaw(Normalize(name));

    public void ByParameterCommandText(string name, NpgsqlCommand cmd)
    {
        var text = Normalize(name);
        // ruleid: labsec.csharp.sql-raw-tainted-input
        cmd.CommandText = text;
    }

    public object Negatives(string name, int id, HttpRequest request, NpgsqlConnection conn, NpgsqlCommand cmd)
    {
        // Constant command text with a parameter value: the safe pattern.
        // ok: labsec.csharp.sql-raw-tainted-input
        var a = new NpgsqlCommand("SELECT * FROM users WHERE name = @name", conn);
        a.Parameters.AddWithValue("name", name);

        // Values passed as format arguments are parameterized by EF Core.
        // ok: labsec.csharp.sql-raw-tainted-input
        var b = ctx.Users.FromSqlRaw("SELECT * FROM users WHERE name = {0}", name);

        // ok: labsec.csharp.sql-raw-tainted-input
        var c = ctx.Users.FromSqlInterpolated($"SELECT * FROM users WHERE name = {name}");

        // A parsed number cannot carry SQL.
        var parsed = int.Parse(request.Query["id"]);
        var text = "SELECT * FROM users WHERE id = " + parsed;
        // ok: labsec.csharp.sql-raw-tainted-input
        // ruleid: labsec.csharp.sql-raw-built-text-variable
        var d = ctx.Users.FromSqlRaw(text);

        // ok: labsec.csharp.sql-raw-tainted-input
        cmd.CommandText = "SELECT 1";

        // ok: labsec.csharp.sql-raw-tainted-input
        return ctx.Users.FromSqlRaw("SELECT * FROM users");
    }

    // ---- ASP.NET Core minimal API handlers ---------------------------------------------------------

    public void MinimalApi(WebApplication app)
    {
        app.MapGet("/users", (string name) =>
        {
            var text = Normalize(name);
            // ruleid: labsec.csharp.sql-raw-tainted-input
            return ctx.Users.FromSqlRaw(text).ToList();
        });

        app.MapPost("/users/delete", async (HttpRequest request, string name) =>
        {
            // ruleid: labsec.csharp.sql-raw-tainted-input
            await ctx.Database.ExecuteSqlRawAsync(Compose(name));
        });

        app.MapGet("/users/{id}", (int id) =>
        {
            // ok: labsec.csharp.sql-raw-tainted-input
            return ctx.Users.FromSqlInterpolated($"SELECT * FROM users WHERE id = {id}").ToList();
        });

        app.MapGet("/users/all", () =>
        {
            // ok: labsec.csharp.sql-raw-tainted-input
            return ctx.Users.FromSqlRaw("SELECT * FROM users").ToList();
        });
    }

    // Text built in place is reported by labsec.csharp.sql-raw-built-text only, not twice.
    public object BuiltInPlace(string name)
    {
        // ok: labsec.csharp.sql-raw-tainted-input
        return ctx.Users.FromSqlRaw($"SELECT * FROM users WHERE name = '{name}'");
    }
}
