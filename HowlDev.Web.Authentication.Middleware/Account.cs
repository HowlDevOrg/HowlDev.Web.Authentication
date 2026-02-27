namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Simple class to hold relevant information from the DB Schema as listed. 
/// </summary>
public class Account {
    /// <summary>
    /// GUID of the user.
    /// </summary>
    public Guid Id { get; set; }
    /// <summary>
    /// Account name of the user. These are enforced to be unique in Postgres. 
    /// </summary>
    public string AccountName { get; set; } = "Default Account Name";
    /// <summary>
    /// Integer role of the account. 
    /// </summary>
    public int Role { get; set; }
}
