#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Test;

namespace fido2_net_lib.Test;

/// <summary>
/// Tests for attestation certificates whose public key is ML-DSA (FIPS 204), as produced by
/// pre-release PQC authenticators that attest with a "packed" statement and an x5c chain.
/// </summary>
public class MLDsaAttestationCertificateTests
{
    // ---- OID mapping ---------------------------------------------------------------------

    [Theory]
    [InlineData(COSE.OidMLDsa44)]
    [InlineData(COSE.OidMLDsa65)]
    [InlineData(COSE.OidMLDsa87)]
    public void GetKeyTypeFromOid_MapsMLDsaOidsToAkp(string oid)
    {
        Assert.Equal(COSE.KeyType.AKP, COSE.GetKeyTypeFromOid(oid));
    }

    [Theory]
    [InlineData(COSE.OidMLDsa44, COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.OidMLDsa65, COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.OidMLDsa87, COSE.Algorithm.ML_DSA_87)]
    public void GetMLDsaAlgorithmFromOid_MapsToCoseAlgorithm(string oid, COSE.Algorithm expected)
    {
        Assert.Equal(expected, COSE.GetMLDsaAlgorithmFromOid(oid));
    }

    [Fact]
    public void GetMLDsaAlgorithmFromOid_RejectsNonMLDsaOid()
    {
        Assert.Throws<ArgumentException>(() => COSE.GetMLDsaAlgorithmFromOid("1.2.840.10045.2.1"));
    }

    // ---- CredentialPublicKey from an ML-DSA certificate ------------------------------------

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public void CredentialPublicKey_FromMLDsaCertificate_VerifiesSignatures(COSE.Algorithm alg)
    {
        if (!MLDsa.IsSupported)
            return;

        using var key = MLDsa.GenerateKey(MLDsaCoseVerifier.Map(alg));
        using var cert = CreateSelfSignedCertificate(key, "CN=ML-DSA attestation test", isCa: false);

        var cpk = new CredentialPublicKey(cert, alg);
        Assert.Equal(alg, cpk.Alg);

        // The generated COSE key must round-trip through the CBOR (AKP) parser.
        var reparsed = new CredentialPublicKey(cpk.GetBytes());
        Assert.Equal(alg, reparsed.Alg);

        byte[] data = RandomNumberGenerator.GetBytes(64);
        byte[] signature = key.SignData(data);

        Assert.True(cpk.Verify(data, signature));
        Assert.True(reparsed.Verify(data, signature));

        signature[0] ^= 0xff;
        Assert.False(cpk.Verify(data, signature));
    }

    [Fact]
    public void CredentialPublicKey_FromMLDsaCertificate_RejectsParameterSetMismatch()
    {
        if (!MLDsa.IsSupported)
            return;

        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var cert = CreateSelfSignedCertificate(key, "CN=ML-DSA attestation test", isCa: false);

        var ex = Assert.Throws<InvalidOperationException>(() => new CredentialPublicKey(cert, COSE.Algorithm.ML_DSA_44));
        Assert.Contains("ML_DSA_65", ex.Message);
    }

    // ---- Packed attestation with an ML-DSA x5c chain (synthetic) ---------------------------

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public async Task PackedAttestation_WithMLDsaX5c_Verifies(COSE.Algorithm credentialAlg)
    {
        if (!MLDsa.IsSupported)
            return;

        // Mirrors the Yubico PQC preview firmware: any ML-DSA credential is attested with an ML-DSA-87 key.
        var fixture = new PackedMLDsaFixture(credentialAlg, COSE.Algorithm.ML_DSA_87);

        var result = await fixture.MakeNewCredentialAsync(fixture.BuildResponse());

        Assert.Equal("packed", result.AttestationFormat);
        Assert.Equal(fixture.AaGuid, result.AaGuid);
        Assert.Equal(fixture.CredentialPublicKey.GetBytes(), result.PublicKey);
        Assert.Equal(credentialAlg, new CredentialPublicKey(result.PublicKey).Alg);
    }

    [Fact]
    public async Task PackedAttestation_WithMLDsaX5c_RejectsTamperedSignature()
    {
        if (!MLDsa.IsSupported)
            return;

        var fixture = new PackedMLDsaFixture(COSE.Algorithm.ML_DSA_44, COSE.Algorithm.ML_DSA_87);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => fixture.MakeNewCredentialAsync(fixture.BuildResponse(tamperSignature: true)));
        Assert.Equal("Invalid full packed signature", ex.Message);
    }

    [Fact]
    public async Task PackedAttestation_WithMLDsaX5c_RejectsAlgorithmNotMatchingCertificate()
    {
        if (!MLDsa.IsSupported)
            return;

        // The certificate holds an ML-DSA-87 key but the statement claims ML-DSA-44.
        var fixture = new PackedMLDsaFixture(COSE.Algorithm.ML_DSA_44, COSE.Algorithm.ML_DSA_87);

        await Assert.ThrowsAnyAsync<Exception>(() => fixture.MakeNewCredentialAsync(fixture.BuildResponse(declaredAttestationAlg: COSE.Algorithm.ML_DSA_44)));
    }

    // ---- Real device vector: YubiKey PQC preview (alpha 8) ---------------------------------

    // Captured 2026-09-16 from a Yubico PQC preview authenticator (AAGUID 2165deef-e5a8-4efa-9fe7-fea9ddb2d227):
    // ML-DSA-87 credential, packed attestation with a 4627-byte ML-DSA-87 signature and a 7618-byte
    // ML-DSA-87 attestation certificate issued by "Yubico 2026-07 FIDO Preview CA" (valid until 2027-12-31).
    private static readonly DateTime _alpha8AttestationCertExpiry = new(2027, 12, 31);
    private static readonly Guid _alpha8AaGuid = new("2165deef-e5a8-4efa-9fe7-fea9ddb2d227");

    private static readonly Fido2Configuration _alpha8Config = new()
    {
        ServerDomain = "localhost",
        ServerName = "FIDO2 Test",
        Origins = new HashSet<string> { "https://localhost:5001" },
    };

    private static bool CanRunAlpha8Vector => MLDsa.IsSupported && DateTime.Now < _alpha8AttestationCertExpiry;

    [Fact]
    public async Task YubicoPqcAlpha8_MLDsa87PackedAttestation_VerifiesWithoutMetadata()
    {
        if (!CanRunAlpha8Vector)
            return;

        var (response, options) = await LoadAlpha8VectorAsync();

        var result = await response.VerifyAsync(options, _alpha8Config, (x, ct) => Task.FromResult(true), metadataService: null, requestTokenBindingId: null, CancellationToken.None);

        Assert.Equal("packed", result.AttestationFormat);
        Assert.Equal(_alpha8AaGuid, result.AaGuid);
        Assert.Equal(COSE.Algorithm.ML_DSA_87, new CredentialPublicKey(result.PublicKey).Alg);
    }

    [Fact]
    public async Task YubicoPqcAlpha8_MLDsa87PackedAttestation_ChainsToYubicoPreviewRoot()
    {
        if (!CanRunAlpha8Vector)
            return;

        var (response, options) = await LoadAlpha8VectorAsync();

        // Local metadata statement for the alpha 8 AAGUID with the three "Yubico 2026-07 FIDO Preview CA"
        // roots (ML-DSA-44/65/87) as trust anchors and attestationTypes = basic_full, so the chain is validated.
        var metadataService = new TestMetadataService([new FileSystemMetadataRepository("./metadata-pqc")]);
        await metadataService.InitializeAsync();

        var result = await response.VerifyAsync(options, _alpha8Config, (x, ct) => Task.FromResult(true), metadataService, requestTokenBindingId: null, CancellationToken.None);

        Assert.Equal("packed", result.AttestationFormat);
        Assert.Equal(_alpha8AaGuid, result.AaGuid);
    }

    [Fact]
    public async Task YubicoPqcAlpha8_MLDsa87PackedAttestation_RejectsUnknownRoot()
    {
        if (!CanRunAlpha8Vector)
            return;

        var (response, options) = await LoadAlpha8VectorAsync();

        // Same statement, but with a freshly generated ML-DSA-87 root as the only trust anchor.
        using var bogusRootKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
        using var bogusRoot = CreateSelfSignedCertificate(bogusRootKey, "CN=Not the Yubico Preview CA", isCa: true);

        var statement = JsonNodeOrThrow(await File.ReadAllTextAsync("./metadata-pqc/yubico-2026-07-fido-preview-pqc-alpha8.json"));
        statement["attestationRootCertificates"] = new System.Text.Json.Nodes.JsonArray(Convert.ToBase64String(bogusRoot.RawData));

        var dir = Path.Combine(Path.GetTempPath(), "fido2-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "alpha8.json"), statement.ToJsonString());

            var metadataService = new TestMetadataService([new FileSystemMetadataRepository(dir)]);
            await metadataService.InitializeAsync();

            var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => response.VerifyAsync(options, _alpha8Config, (x, ct) => Task.FromResult(true), metadataService, requestTokenBindingId: null, CancellationToken.None));
            Assert.Equal(Fido2ErrorMessages.InvalidCertificateChainFull, ex.Message);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static async Task<(AuthenticatorAttestationResponse Response, CredentialCreateOptions Options)> LoadAlpha8VectorAsync()
    {
        var raw = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync("./attestationYubicoPqcAlpha8MlDsa87.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync("./attestationOptionsYubicoPqcAlpha8MlDsa87.json"));
        return (AuthenticatorAttestationResponse.Parse(raw), options);
    }

    private static System.Text.Json.Nodes.JsonObject JsonNodeOrThrow(string json)
    {
        return System.Text.Json.Nodes.JsonNode.Parse(json)?.AsObject() ?? throw new InvalidOperationException("Invalid JSON");
    }

    // ---- Helpers ---------------------------------------------------------------------------

    internal static X509Certificate2 CreateSelfSignedCertificate(MLDsa key, string subject, bool isCa)
    {
        var request = new CertificateRequest(new X500DistinguishedName(subject), key);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, isCa));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>
    /// Builds a packed attestation for an ML-DSA credential, signed by an ML-DSA attestation key whose
    /// certificate is issued by a self-signed ML-DSA root (the shape produced by the Yubico PQC preview keys).
    /// </summary>
    private sealed class PackedMLDsaFixture
    {
        private const string Rp = "localhost";
        private const string Origin = "https://localhost:5001";

        private readonly MLDsa _attestationKey;
        private readonly X509Certificate2 _attestationCert;
        private readonly X509Certificate2 _root;
        private readonly COSE.Algorithm _attestationAlg;
        private readonly byte[] _challenge = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _credentialId = RandomNumberGenerator.GetBytes(32);

        public Guid AaGuid { get; } = new("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        public CredentialPublicKey CredentialPublicKey { get; }

        public PackedMLDsaFixture(COSE.Algorithm credentialAlg, COSE.Algorithm attestationAlg)
        {
            _attestationAlg = attestationAlg;

            // Credential key (AKP COSE key)
            using var credentialKey = MLDsa.GenerateKey(MLDsaCoseVerifier.Map(credentialAlg));
            var cpk = new CborMap
            {
                { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
                { (long)COSE.KeyCommonParameter.Alg, (long)credentialAlg }
            };
            cpk.Add(-1L, credentialKey.ExportMLDsaPublicKey());
            CredentialPublicKey = new CredentialPublicKey(cpk);

            // Attestation root and attestation (leaf) certificate, both ML-DSA
            using var rootKey = MLDsa.GenerateKey(MLDsaCoseVerifier.Map(attestationAlg));
            _root = CreateSelfSignedCertificate(rootKey, "CN=Testing ML-DSA Root, O=FIDO2-NET-LIB, C=US", isCa: true);

            _attestationKey = MLDsa.GenerateKey(MLDsaCoseVerifier.Map(attestationAlg));
            var leafRequest = new CertificateRequest(new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US"), _attestationKey);
            leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            leafRequest.CertificateExtensions.Add(new X509Extension(new Oid("1.3.6.1.4.1.45724.1.1.4"), [0x04, 0x10, .. AaGuid.ToByteArray(bigEndian: true)], false));
            _attestationCert = leafRequest.Create(_root.SubjectName, X509SignatureGenerator.CreateForMLDsa(rootKey), DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(12));
        }

        public AuthenticatorAttestationRawResponse BuildResponse(bool tamperSignature = false, COSE.Algorithm? declaredAttestationAlg = null)
        {
            var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(Rp));
            var acd = new AttestedCredentialData(AaGuid, _credentialId, CredentialPublicKey);
            var authData = new AuthenticatorData(rpIdHash, AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV, 1, acd).ToByteArray();

            var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
            {
                Type = "webauthn.create",
                Challenge = _challenge,
                Origin = Origin
            });

            byte[] toBeSigned = [.. authData, .. SHA256.HashData(clientDataJson)];
            byte[] signature = _attestationKey.SignData(toBeSigned);
            if (tamperSignature)
                signature[^1] ^= 0xff;

            var attStmt = new CborMap
            {
                { "alg", (int)(declaredAttestationAlg ?? _attestationAlg) },
                { "sig", signature },
                { "x5c", new CborArray { _attestationCert.RawData, _root.RawData } }
            };

            var attestationObject = new CborMap
            {
                { "fmt", "packed" },
                { "attStmt", attStmt },
                { "authData", authData }
            };

            return new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = Convert.ToBase64String(_credentialId),
                RawId = _credentialId,
                Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                {
                    AttestationObject = attestationObject.Encode(),
                    ClientDataJson = clientDataJson,
                    Transports = [AuthenticatorTransport.Usb]
                }
            };
        }

        public Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(AuthenticatorAttestationRawResponse response)
        {
            var options = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Preferred,
                    UserVerification = UserVerificationRequirement.Preferred,
                },
                Challenge = _challenge,
                PubKeyCredParams = [PubKeyCredParam.ML_DSA_44, PubKeyCredParam.ML_DSA_65, PubKeyCredParam.ML_DSA_87, PubKeyCredParam.ES256],
                Rp = new PublicKeyCredentialRpEntity(Rp, "FIDO2 Test", ""),
                User = new Fido2User
                {
                    Name = "pqc-user",
                    Id = "pqc-user"u8.ToArray(),
                    DisplayName = "PQC user",
                },
                Timeout = 60000,
            };

            var lib = new Fido2(new Fido2Configuration
            {
                ServerDomain = Rp,
                ServerName = "FIDO2 Test",
                Origins = new HashSet<string> { Origin },
            });

            return lib.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = response,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = (args, ct) => Task.FromResult(true)
            });
        }
    }
}

#pragma warning restore SYSLIB5006
