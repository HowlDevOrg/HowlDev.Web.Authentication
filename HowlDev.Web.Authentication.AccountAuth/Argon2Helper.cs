using Konscious.Security.Cryptography;
using System.Security.Cryptography;

namespace HowlDev.Web.Authentication.AccountAuth;

/// <summary>
/// An AI-generated class to hash and validate hashes, using the Konscious cryptography library. 
/// </summary>
internal static class Argon2Helper {
    /// <summary>
    /// Generates a new random salt and includes it in the return string. 
    /// </summary>
    public static string HashPassword(string password, Argon2Options options) {
        byte[] salt = RandomNumberGenerator.GetBytes(options.SaltSize);

        var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password)) {
            Salt = salt,
            DegreeOfParallelism = options.Parallelism,
            Iterations = options.Iterations,
            MemorySize = options.MemoryKB   // expressed in KiB
        };

        byte[] hash = argon2.GetBytes(options.HashSize);

        //    Format: $argon2id$v=19$m=131072,t=2,p=4$<base64(salt)>$<base64(hash)>
        string encoded = string.Concat(
            "$argon2id$",
            $"m={options.MemoryKB},t={options.Iterations},p={options.Parallelism}$",
            Convert.ToBase64String(salt), "$",
            Convert.ToBase64String(hash));

        return encoded;
    }

    /// <summary>
    /// Given an input hash string, validates that the two passwords are equal. 
    /// </summary>
    /// <exception cref="FormatException"></exception>
    public static bool VerifyPassword(string encodedHash, string passwordAttempt) {
        // Expected format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
        var parts = encodedHash.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4 || parts[0] != "argon2id")
            throw new FormatException("Invalid Argon2 hash format.");

        // ---- parse the parameter block ----
        // Example: "v=19$m=131072,t=2,p=4"
        var paramBlock = parts[1];
        var paramPairs = paramBlock.Split(',', StringSplitOptions.RemoveEmptyEntries);
        int memory = 0, iterations = 0, parallelism = 0;
        foreach (var pair in paramPairs) {
            var kv = pair.Split('=', 2);
            if (kv.Length != 2) continue;
            switch (kv[0]) {
                case "m": memory = int.Parse(kv[1]); break;
                case "t": iterations = int.Parse(kv[1]); break;
                case "p": parallelism = int.Parse(kv[1]); break;
                    // ignore version (v=19) – we only support Argon2id v=19
            }
        }

        byte[] salt = Convert.FromBase64String(parts[2]);
        byte[] expectedHash = Convert.FromBase64String(parts[3]);

        var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(passwordAttempt)) {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            Iterations = iterations,
            MemorySize = memory
        };

        byte[] actualHash = argon2.GetBytes(expectedHash.Length);

        // Constant‑time compare
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}
