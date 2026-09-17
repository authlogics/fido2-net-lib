using System.Security.Cryptography.X509Certificates;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Fido2Demo.Pages;

public class dashboardModel : PageModel
{
    private readonly IMetadataService _metadataService;
    private readonly ILogger<dashboardModel> _logger;

    public dashboardModel(IMetadataService metadataService, ILogger<dashboardModel> logger)
    {
        _metadataService = metadataService;
        _logger = logger;
    }

    public string Username { get; private set; }

    public List<CredentialRow> Credentials { get; } = [];

    public int PqcCount => Credentials.Count(c => c.IsPqc);

    public int ClassicalCount => Credentials.Count - PqcCount;

    public async Task OnGetAsync(string username)
    {
        Username = username;

        // Please know that this is not good for production: the demo keeps credentials in memory only.
        var user = DemoController.DemoStorage.GetUser(username);
        if (user is null)
            return;

        foreach (var stored in DemoController.DemoStorage.GetCredentialsByUser(user))
        {
            Credentials.Add(await BuildRowAsync(stored));
        }
    }

    private async Task<CredentialRow> BuildRowAsync(StoredCredential stored)
    {
        var key = DescribePublicKey(stored.PublicKey);
        var attestation = DescribeAttestation(stored);
        var (authenticator, icon) = await DescribeAuthenticatorAsync(stored.AaGuid);

        return new CredentialRow
        {
            Registered = stored.RegDate,
            AaGuid = stored.AaGuid,
            Authenticator = authenticator,
            AuthenticatorIcon = icon,
            Transports = stored.Transports is { Length: > 0 } ? string.Join(", ", stored.Transports.Select(t => t.ToString().ToLowerInvariant())) : "",
            Algorithm = key.Algorithm,
            AlgorithmName = AlgorithmName(key.Algorithm),
            IsPqc = IsPqc(key.Algorithm),
            KeyType = key.KeyType,
            PublicKeySizeBytes = key.SizeBytes,
            PublicKeySizeDetail = key.SizeDetail,
            PublicKeyBase64 = key.RawKeyBase64,
            CoseKeySizeBytes = stored.PublicKey.Length,
            CoseKeyBase64 = Convert.ToBase64String(stored.PublicKey),
            SignatureSize = key.SignatureSize,
            AttestationFormat = attestation.Format,
            AttestationSummary = attestation.Summary,
            AttestationIsPqc = attestation.IsPqc,
            AttestationChainValidationSkipped = stored.AttestationChainValidationSkipped,
        };
    }

    // ---- Public key --------------------------------------------------------------------------

    private sealed record PublicKeyInfo(COSE.Algorithm Algorithm, string KeyType, int SizeBytes, string SizeDetail, string RawKeyBase64, string SignatureSize);

    private static PublicKeyInfo DescribePublicKey(byte[] cpkBytes)
    {
        var cpk = new CredentialPublicKey(cpkBytes);

        // Collect the COSE key parameters by integer label.
        var byteParams = new Dictionary<long, byte[]>();
        var intParams = new Dictionary<long, long>();
        foreach (var (label, value) in cpk.GetCborObject())
        {
            long key;
            try
            { key = (long)label; }
            catch { continue; }

            if (value is CborByteString bytes)
                byteParams[key] = bytes.Value;
            else
            {
                try
                { intParams[key] = (long)value; }
                catch { /* not an integer */ }
            }
        }

        var keyType = (COSE.KeyType)intParams.GetValueOrDefault((long)COSE.KeyCommonParameter.KeyType);

        switch (keyType)
        {
            case COSE.KeyType.AKP:
                {
                    var pub = byteParams.GetValueOrDefault(-1) ?? [];
                    return new(cpk.Alg, "AKP (ML-DSA)", pub.Length, "raw FIPS 204 public key",
                        Convert.ToBase64String(pub), $"{COSE.GetMLDsaSignatureSize(cpk.Alg)} B");
                }
            case COSE.KeyType.EC2:
                {
                    var x = byteParams.GetValueOrDefault(-2) ?? [];
                    var y = byteParams.GetValueOrDefault(-3) ?? [];
                    var curve = CurveName((COSE.EllipticCurve)intParams.GetValueOrDefault(-1));
                    byte[] point = [.. x, .. y];
                    return new(cpk.Alg, $"EC2 ({curve})", point.Length, $"x {x.Length} B + y {y.Length} B",
                        Convert.ToBase64String(point), $"~{2 * x.Length + 6} B (DER)");
                }
            case COSE.KeyType.RSA:
                {
                    var n = byteParams.GetValueOrDefault(-1) ?? [];
                    var e = byteParams.GetValueOrDefault(-2) ?? [];
                    return new(cpk.Alg, $"RSA-{n.Length * 8}", n.Length, $"modulus {n.Length} B, exponent {e.Length} B",
                        Convert.ToBase64String(n), $"{n.Length} B");
                }
            case COSE.KeyType.OKP:
                {
                    var x = byteParams.GetValueOrDefault(-2) ?? [];
                    return new(cpk.Alg, "OKP (Ed25519)", x.Length, "raw Ed25519 public key",
                        Convert.ToBase64String(x), "64 B");
                }
            default:
                return new(cpk.Alg, keyType.ToString(), cpkBytes.Length, "COSE key", Convert.ToBase64String(cpkBytes), "");
        }
    }

    // ---- Attestation -------------------------------------------------------------------------

    private sealed record AttestationInfo(string Format, string Summary, bool IsPqc);

    private AttestationInfo DescribeAttestation(StoredCredential stored)
    {
        var format = stored.AttestationFormat ?? "unknown";

        if (stored.AttestationObject is not { Length: > 0 })
            return new(format, "", false);

        try
        {
            var attestationObject = (CborMap)CborObject.Decode(stored.AttestationObject);

            if (attestationObject["fmt"] is CborTextString fmt)
                format = fmt.Value;

            if (format == "none")
                return new(format, "statement removed by the browser or platform (attestation preference \"none\")", false);

            if (attestationObject["attStmt"] is not CborMap attStmt || attStmt.Count == 0)
                return new(format, "", false);

            var parts = new List<string>();
            bool isPqc = false;

            if (attStmt["alg"] is { } algObject)
            {
                var alg = (COSE.Algorithm)(long)algObject;
                var signatureSize = attStmt["sig"] is CborByteString sig ? $" {sig.Length} B" : "";
                parts.Add($"{AlgorithmName(alg)} signature{signatureSize}");
                isPqc |= IsPqc(alg);
            }

            if (attStmt["x5c"] is CborArray { Length: > 0 } x5c && x5c[0] is CborByteString leafBytes)
            {
                try
                {
                    using var leaf = X509CertificateLoader.LoadCertificate(leafBytes.Value);
                    var keyType = COSE.GetKeyTypeFromOid(leaf.GetKeyAlgorithm());
                    var certificateKey = keyType == COSE.KeyType.AKP
                        ? AlgorithmName(COSE.GetMLDsaAlgorithmFromOid(leaf.GetKeyAlgorithm()))
                        : CertificateKeyName(leaf, keyType);
                    parts.Add($"{certificateKey} attestation certificate {leafBytes.Length} B");
                    isPqc |= keyType == COSE.KeyType.AKP;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Could not describe attestation certificate");
                    parts.Add($"attestation certificate {leafBytes.Length} B");
                }

                if (x5c.Length > 1)
                    parts.Add($"{x5c.Length - 1} more certificate(s) in chain");
            }
            else
            {
                parts.Add("self-attestation (signed with the credential key)");
            }

            return new(format, string.Join(", ", parts), isPqc);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not parse stored attestation object");
            return new(format, "", false);
        }
    }

    private static string CertificateKeyName(X509Certificate2 certificate, COSE.KeyType keyType)
    {
        return keyType switch
        {
            COSE.KeyType.EC2 => $"ECDSA P-{certificate.GetECDsaPublicKey()?.KeySize}",
            COSE.KeyType.RSA => $"RSA-{certificate.GetRSAPublicKey()?.KeySize}",
            COSE.KeyType.OKP => "Ed25519",
            _ => keyType.ToString()
        };
    }

    // ---- Authenticator metadata --------------------------------------------------------------

    private async Task<(string Description, string Icon)> DescribeAuthenticatorAsync(Guid aaGuid)
    {
        if (aaGuid == Guid.Empty)
            return ("Not disclosed (attestation \"none\" zeroes the AAGUID)", null);

        try
        {
            var entry = await _metadataService.GetEntryAsync(aaGuid, HttpContext.RequestAborted);
            if (entry?.MetadataStatement is { } statement)
                return (statement.Description, statement.Icon);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Metadata lookup failed for AAGUID {AaGuid}", aaGuid);
        }

        return ("Unknown authenticator (no metadata)", null);
    }

    // ---- Naming helpers ----------------------------------------------------------------------

    public static bool IsPqc(COSE.Algorithm alg) => alg is COSE.Algorithm.ML_DSA_44 or COSE.Algorithm.ML_DSA_65 or COSE.Algorithm.ML_DSA_87;

    // Short, human-readable names of COSE algorithms. https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    public static string AlgorithmName(COSE.Algorithm alg) => alg switch
    {
        COSE.Algorithm.RS1 => "RSASSA-PKCS1-v1_5 / SHA-1",
        COSE.Algorithm.RS256 => "RS256",
        COSE.Algorithm.RS384 => "RS384",
        COSE.Algorithm.RS512 => "RS512",
        COSE.Algorithm.PS256 => "PS256",
        COSE.Algorithm.PS384 => "PS384",
        COSE.Algorithm.PS512 => "PS512",
        COSE.Algorithm.ES256 => "ES256",
        COSE.Algorithm.ES384 => "ES384",
        COSE.Algorithm.ES512 => "ES512",
        COSE.Algorithm.ES256K => "ES256K",
        COSE.Algorithm.EdDSA => "EdDSA",
        COSE.Algorithm.ML_DSA_44 => "ML-DSA-44",
        COSE.Algorithm.ML_DSA_65 => "ML-DSA-65",
        COSE.Algorithm.ML_DSA_87 => "ML-DSA-87",
        _ => alg.ToString()
    };

    private static string CurveName(COSE.EllipticCurve curve) => curve switch
    {
        COSE.EllipticCurve.P256 => "P-256",
        COSE.EllipticCurve.P384 => "P-384",
        COSE.EllipticCurve.P521 => "P-521",
        COSE.EllipticCurve.P256K => "secp256k1",
        _ => curve.ToString()
    };

    public sealed class CredentialRow
    {
        public DateTimeOffset Registered { get; init; }
        public Guid AaGuid { get; init; }
        public string Authenticator { get; init; }
        public string AuthenticatorIcon { get; init; }
        public string Transports { get; init; }
        public COSE.Algorithm Algorithm { get; init; }
        public string AlgorithmName { get; init; }
        public bool IsPqc { get; init; }
        public string KeyType { get; init; }
        public int PublicKeySizeBytes { get; init; }
        public string PublicKeySizeDetail { get; init; }
        public string PublicKeyBase64 { get; init; }
        public int CoseKeySizeBytes { get; init; }
        public string CoseKeyBase64 { get; init; }
        public string SignatureSize { get; init; }
        public string AttestationFormat { get; init; }
        public string AttestationSummary { get; init; }
        public bool AttestationIsPqc { get; init; }
        public bool AttestationChainValidationSkipped { get; init; }
    }
}
