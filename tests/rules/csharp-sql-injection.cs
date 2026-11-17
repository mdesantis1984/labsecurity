using System.Text;
using Microsoft.EntityFrameworkCore;
using Npgsql;

public class Repo
{
    private readonly AppDbContext ctx;

    public void Positive(string name, NpgsqlConnection conn, NpgsqlCommand cmd)
    {
        // ruleid: labsec.csharp.sql-raw-built-text
        var a = ctx.Users.FromSqlRaw($"SELECT * FROM users WHERE name = '{name}'");
        // ruleid: labsec.csharp.sql-raw-built-text
        var b = ctx.Users.FromSqlRaw("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: labsec.csharp.sql-raw-built-text
        var c = ctx.Users.FromSqlRaw(string.Format("SELECT * FROM users WHERE name = '{0}'", name));
        // ruleid: labsec.csharp.sql-raw-built-text
        ctx.Database.ExecuteSqlRaw($"DELETE FROM users WHERE name = '{name}'");
        // ruleid: labsec.csharp.sql-raw-built-text
        ctx.Database.ExecuteSqlRawAsync("DELETE FROM users WHERE name = '" + name + "'");
        // ruleid: labsec.csharp.sql-raw-built-text
        ctx.Database.SqlQueryRaw<int>($"SELECT id FROM users WHERE name = '{name}'");
        // ruleid: labsec.csharp.sql-raw-built-text
        var d = new NpgsqlCommand($"SELECT * FROM users WHERE name = '{name}'", conn);
        // ruleid: labsec.csharp.sql-raw-built-text
        var e = new NpgsqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        // ruleid: labsec.csharp.sql-raw-built-text
        cmd.CommandText = $"SELECT * FROM users WHERE name = '{name}'";
        // ruleid: labsec.csharp.sql-raw-built-text
        cmd.CommandText = "SELECT * FROM users WHERE name = '" + name + "'";
    }

    public void Negative(string name, NpgsqlConnection conn, NpgsqlCommand cmd)
    {
        // ok: labsec.csharp.sql-raw-built-text
        var a = ctx.Users.FromSqlInterpolated($"SELECT * FROM users WHERE name = {name}");
        // ok: labsec.csharp.sql-raw-built-text
        ctx.Database.ExecuteSqlInterpolated($"DELETE FROM users WHERE name = {name}");
        // ok: labsec.csharp.sql-raw-built-text
        ctx.Database.SqlQuery<int>($"SELECT id FROM users WHERE name = {name}");
        // ok: labsec.csharp.sql-raw-built-text
        var b = ctx.Users.FromSqlRaw("SELECT * FROM users WHERE name = {0}", name);
        // ok: labsec.csharp.sql-raw-built-text
        var c = ctx.Users.FromSqlRaw("SELECT * FROM users");
        // ok: labsec.csharp.sql-raw-built-text
        var d = ctx.Users.FromSqlRaw("SELECT * " + "FROM users");
        // ok: labsec.csharp.sql-raw-built-text
        ctx.Database.ExecuteSqlRaw("DELETE FROM users WHERE name = @name", new NpgsqlParameter("name", name));
        // ok: labsec.csharp.sql-raw-built-text
        var e = new NpgsqlCommand("SELECT * FROM users WHERE name = @name", conn);
        // ok: labsec.csharp.sql-raw-built-text
        e.Parameters.AddWithValue("name", name);
        // ok: labsec.csharp.sql-raw-built-text
        cmd.CommandText = "SELECT * FROM users WHERE name = @name";
        // ok: labsec.csharp.sql-raw-built-text
        cmd.Parameters.Add(new NpgsqlParameter("name", name));
    }

    private const string Table = "users";
    private const string Columns = "id, name";

    public void ConstantHoles(string name, NpgsqlConnection conn, NpgsqlCommand cmd)
    {
        // ok: labsec.csharp.sql-raw-built-text
        var a = ctx.Users.FromSqlRaw($"SELECT {Columns} FROM {Table} WHERE name = @name", new NpgsqlParameter("name", name));
        // ok: labsec.csharp.sql-raw-built-text
        var b = ctx.Users.FromSqlRaw("SELECT " + Columns + " FROM " + Table + " WHERE name = @name", new NpgsqlParameter("name", name));
        // ok: labsec.csharp.sql-raw-built-text
        var c = new NpgsqlCommand($"SELECT * FROM {nameof(Repo)} WHERE name = @name", conn);
        // ok: labsec.csharp.sql-raw-built-text
        cmd.CommandText = $"SELECT {"id"} FROM users WHERE rank > {1} AND name = @name";

        // A hole that is not constant keeps the finding.
        // ruleid: labsec.csharp.sql-raw-built-text
        var d = ctx.Users.FromSqlRaw($"SELECT {Columns} FROM {name} WHERE id = @id", new NpgsqlParameter("id", 1));
        // ruleid: labsec.csharp.sql-raw-built-text
        var e = ctx.Users.FromSqlRaw($"SELECT * FROM {nameof(Repo)} WHERE name = '{name}'");
        // ruleid: labsec.csharp.sql-raw-built-text
        cmd.CommandText = "SELECT * FROM " + Table + " WHERE name = '" + name + "'";
    }
}
