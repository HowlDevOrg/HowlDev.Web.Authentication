namespace HowlDev.Web.Authentication.AccountAuth;

/// <summary>
/// Argon2 configurations for the internal hashing system. Leave most default
/// </summary>
public class Argon2Options(int iterations = 2, int megabytes = 128, int threads = 4) {
    // Default parameters – tune to your hardware and security policy
    /// <summary>
    /// Defaults to 128 bits. Don't recommend changing.
    /// </summary>
    public int SaltSize = 16;
    /// <summary>
    /// Defaults to 256 bits. Don't recommend changing.
    /// </summary>
    public int HashSize = 32;
    /// <summary>
    /// Number of passes to perform.
    /// </summary>
    public int Iterations = iterations;
    /// <summary>
    /// Number of kilobytes to take up. Recommended to go through the constructor
    /// or, if you set it yourself, multiply by 1024.
    /// </summary>
    public int MemoryKB = megabytes * 1024;
    /// <summary>
    /// Number of threads to use. Defaults to 4 in the constructor.
    /// </summary>
    public int Parallelism = threads;
}
