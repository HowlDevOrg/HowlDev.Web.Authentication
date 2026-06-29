using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Encapsulates Account Name, ApiKey, Role, and Guid of the incoming request. 
/// Enables smoother encapsulation for endpoints, just use this as a parameter and it 
/// will collect the information for you, or appropriately throw errors. 
/// </summary>
public class TryAccountInfo {
    /// <summary>
    /// Account Name of the incoming request
    /// </summary>
    public string? AccountName { get; }
    /// <summary>
    /// Api Key of the incoming request
    /// </summary>
    public string? ApiKey { get; }
    /// <summary>
    /// Guid of the incoming request
    /// </summary>
    public Guid? Guid { get; }
    /// <summary>
    /// Role of the incoming user
    /// </summary>
    public int? Role { get; }
    /// <summary>
    /// The values in this object are valid
    /// </summary>
    [MemberNotNullWhen(true, nameof(AccountName))]
    [MemberNotNullWhen(true, nameof(ApiKey))]
    [MemberNotNullWhen(true, nameof(Guid))]
    [MemberNotNullWhen(true, nameof(Role))]
    public bool IsValid { get; }

    private TryAccountInfo() {
        IsValid = false;
    }

    private TryAccountInfo(string accountName, string apiKey, Guid guid, int role) {
        AccountName = accountName;
        ApiKey = apiKey;
        Guid = guid;
        Role = role;
        IsValid = true;
    }

    /// <summary>
    /// Is this even visible? I don't think so. 
    /// </summary>
    public static ValueTask<TryAccountInfo> BindAsync(HttpContext context) {
        if (!context.Items.ContainsKey(MagicStrings.HttpContextAcc)) {
            return ValueTask.FromResult(new TryAccountInfo());
        }

        string accountName = (string)context.Items[MagicStrings.HttpContextAcc]!;
        string apiKey = (string)context.Items[MagicStrings.HttpContextKey]!;
        Guid guid = (Guid)context.Items[MagicStrings.HttpContextGuid]!;
        int role = (int)context.Items[MagicStrings.HttpContextRole]!;

        return ValueTask.FromResult(new TryAccountInfo(accountName!, apiKey!, guid, role));
    }
}
