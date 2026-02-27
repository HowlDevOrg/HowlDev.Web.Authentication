using HowlDev.Web.Authentication.AccountAuth;
using HowlDev.Web.Authentication.Middleware;
using System.Net;
using System.Text.RegularExpressions;
using TestingAPI;

var builder = WebApplication.CreateBuilder(args);

//var connString = builder.Configuration["DOTNET_DATABASE_STRING"] ?? throw new InvalidOperationException("Connection string for database not found.");
//var connString = "Host=localhost;Database=accountAuth;Username=cody;Password=123456abc;";
//Console.WriteLine("Connection String: " + connString);
//builder.Services.AddSingleton<DbConnector>();
builder.AddAuthService();
builder.Services.AddLogging();

var app = builder.Build();

app.UseAccountIdentityMiddleware(options => {
    options.Paths = ["/users", "/user", "/user/signin", "/health"];
    options.RegexPaths = [new Regex("ws/[1-9]+")];
    // options.HeaderAccount = "Lorem-Account"; // This works as expected
    // options.DisableHeaderInfo = true;
    // options.ExpirationDate = new TimeSpan(1, 0, 0, 0);
    // options.EnableLogging = true;
});

app.UseRouting();

app.MapGet("/health", () => "Hello");

app.MapGet("/users", async (AuthService service) => await service.GetAllUsersAsync());
app.MapGet("/user/exact", async (AuthService service, string account) => await service.GetUserAsync(account));
app.MapGet("/user/count", async (AuthService service, string account) => await service.GetCurrentSessionCountAsync(account));
app.MapPost("/user", async (AuthService service, string accountName) => {
    try {
        await service.AddUserAsync(accountName);
        return Results.Created();
    } catch (Exception e) {
        return Results.BadRequest(e.Message);
    }
});

app.MapPost("/user/signin", async (AuthService service, SignIn obj) => {
    if (await service.IsValidUserPassAsync(obj.user, obj.pass)) {
        return Results.Ok(await service.NewSignInAsync(obj.user));
    } else {
        return Results.BadRequest("Invalid Account/Password combo.");
    }
});

app.MapPatch("/user", async (AuthService service, SignIn obj) => {
    await service.UpdatePasswordAsync(obj.user, obj.pass);
    return Results.Ok();
});
app.MapPatch("/user/role", async (AuthService service, AccountInfo info, int newRole) => {
    await service.UpdateRoleAsync(info.AccountName, newRole);
    return Results.Ok();
});

app.MapGet("/user/valid", () => Results.Ok());
app.MapGet("/user/guid", (AccountInfo info) => info.Guid);
app.MapGet("/user/role", (AccountInfo info) => info.Role);

app.MapGet("/user/role/gt/{role}", (int role, AuthService svc) => svc.QueryUsersAboveRoleAsync(role));
app.MapGet("/user/guid/get", (AccountInfo info, AuthService svc) => svc.GetAccountNameAsync(info.Guid));
app.MapGet("/user/query", (string query, AuthService svc) => svc.QueryUsersAsync(query));

app.MapDelete("/user/signout", async (AuthService service, AccountInfo info) => {
    await service.KeySignOutAsync(info.AccountName, info.ApiKey);

    return Results.Accepted();
});
app.MapDelete("/user/signout/global", async (AuthService service, AccountInfo info) => {
    await service.GlobalSignOutAsync(info.AccountName);

    return Results.Accepted();
});

app.MapGet("/filters/et", () => Results.Ok()).RequireRoleIsEqualTo(3);
app.MapGet("/filters/gt", () => Results.Ok()).RequireRoleIsGreaterThan(1);
app.MapGet("/filters/lt", () => Results.Ok()).RequireRoleIsLessThan(10, HttpStatusCode.Forbidden);
app.MapGet("/filters/gte", () => Results.Ok()).RequireRoleIsGreaterThanOrEqualTo(3);
app.MapGet("/filters/lte", () => Results.Ok()).RequireRoleIsLessThanOrEqualTo(3, 423);
app.MapGet("/filters/custom", () => Results.Ok()).RequireRoleIs(i => i % 3 == 0);

app.MapGet("/filters/string", () => Results.Ok()).RequireAccountNameIsEqualTo("Cody");
app.MapGet("/filters/stringis", () => Results.Ok()).RequireAccountNameIs(s => s.Length < 3);

app.MapGet("/ws/{id}", (int id) => id);

app.Run();

#pragma warning disable CA1050
public partial class AuthProgram { }
