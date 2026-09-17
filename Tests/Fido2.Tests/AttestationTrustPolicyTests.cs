#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Test;

namespace fido2_net_lib.Test;

/// <summary>
/// Tests for <see cref="AttestationTrustPolicy"/>: per-AAGUID opt-out of attestation certificate chain
/// validation, separately for classical and post-quantum attestation certificates.
/// Uses two real responses from a Yubico PQC preview key (AAGUID 2165deef-...): an ES256 credential
/// whose ECDSA attestation certificate chains to a CA that is not in the local metadata statement, and
/// an ML-DSA-87 credential whose ML-DSA-87 attestation certificate chains to the statement's roots.
/// </summary>
public class AttestationTrustPolicyTests
{
    private static readonly Guid _alpha8AaGuid = new("2165deef-e5a8-4efa-9fe7-fea9ddb2d227");

    // The captured attestation certificates expire on these dates; the vector tests self-skip afterwards.
    private static bool CanRunEs256Vector => MLDsa.IsSupported && DateTime.Now < new DateTime(2028, 1, 6);
    private static bool CanRunMlDsaVector => MLDsa.IsSupported && DateTime.Now < new DateTime(2027, 12, 31);

    private static Fido2Configuration CreateConfig(params AttestationTrustPolicy[] policies) => new()
    {
        ServerDomain = "localhost",
        ServerName = "FIDO2 Test",
        Origins = new HashSet<string> { "https://localhost:5001" },
        AttestationTrustPolicies = policies,
    };

    private static AttestationTrustPolicy Alpha8Policy(bool bypassClassical, bool bypassPostQuantum) => new()
    {
        AaGuid = _alpha8AaGuid,
        BypassClassicalChainValidation = bypassClassical,
        BypassPostQuantumChainValidation = bypassPostQuantum,
    };

    // ---- Classical attestation certificate with an unknown issuer ----------------------------

    [Fact]
    public async Task ClassicalChain_UnknownRoot_FailsWithoutPolicy()
    {
        if (!CanRunEs256Vector)
            return;

        var (response, options) = await LoadVectorAsync("Es256");
        var metadata = await Alpha8MetadataServiceAsync();

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verify(response, options, CreateConfig(), metadata));
        Assert.Equal(Fido2ErrorMessages.InvalidCertificateChainFull, ex.Message);
    }

    [Fact]
    public async Task ClassicalChain_UnknownRoot_PassesWithClassicalBypass()
    {
        if (!CanRunEs256Vector)
            return;

        var (response, options) = await LoadVectorAsync("Es256");
        var metadata = await Alpha8MetadataServiceAsync();

        var result = await Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: true, bypassPostQuantum: false)), metadata);

        Assert.True(result.AttestationChainValidationSkipped);
        Assert.Equal("packed", result.AttestationFormat);
        Assert.Equal(_alpha8AaGuid, result.AaGuid);
        Assert.Equal(COSE.Algorithm.ES256, new CredentialPublicKey(result.PublicKey).Alg);
    }

    [Fact]
    public async Task ClassicalChain_UnknownRoot_PostQuantumBypassDoesNotApply()
    {
        if (!CanRunEs256Vector)
            return;

        var (response, options) = await LoadVectorAsync("Es256");
        var metadata = await Alpha8MetadataServiceAsync();

        await Assert.ThrowsAsync<Fido2VerificationException>(() => Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: false, bypassPostQuantum: true)), metadata));
    }

    [Fact]
    public async Task ClassicalChain_PolicyForOtherAaGuid_DoesNotApply()
    {
        if (!CanRunEs256Vector)
            return;

        var (response, options) = await LoadVectorAsync("Es256");
        var metadata = await Alpha8MetadataServiceAsync();
        var otherDevice = new AttestationTrustPolicy { AaGuid = Guid.NewGuid(), BypassClassicalChainValidation = true, BypassPostQuantumChainValidation = true };

        await Assert.ThrowsAsync<Fido2VerificationException>(() => Verify(response, options, CreateConfig(otherDevice), metadata));
    }

    [Fact]
    public async Task ClassicalChain_PolicyIgnoredWhileConformanceTesting()
    {
        if (!CanRunEs256Vector)
            return;

        var (response, options) = await LoadVectorAsync("Es256");
        var metadata = new ConformanceModeMetadataService(await Alpha8MetadataServiceAsync());

        await Assert.ThrowsAsync<Fido2VerificationException>(() => Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: true, bypassPostQuantum: true)), metadata));
    }

    // ---- Post-quantum attestation certificate ------------------------------------------------

    [Fact]
    public async Task PostQuantumChain_KnownRoot_IsStillValidatedWhenOnlyClassicalIsBypassed()
    {
        if (!CanRunMlDsaVector)
            return;

        var (response, options) = await LoadVectorAsync("MlDsa87");
        var metadata = await Alpha8MetadataServiceAsync();

        var result = await Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: true, bypassPostQuantum: false)), metadata);

        Assert.False(result.AttestationChainValidationSkipped);
        Assert.Equal(COSE.Algorithm.ML_DSA_87, new CredentialPublicKey(result.PublicKey).Alg);
    }

    [Fact]
    public async Task PostQuantumChain_UnknownRoot_PassesOnlyWithPostQuantumBypass()
    {
        if (!CanRunMlDsaVector)
            return;

        var (response, options) = await LoadVectorAsync("MlDsa87");

        // Same statement, but with a freshly generated ML-DSA-87 root as the only trust anchor.
        using var bogusRootKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
        var bogusRootRequest = new CertificateRequest(new X500DistinguishedName("CN=Not the Yubico Preview CA"), bogusRootKey);
        bogusRootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var bogusRoot = bogusRootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var dir = Path.Combine(Path.GetTempPath(), "fido2-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var statement = JsonNode.Parse(await File.ReadAllTextAsync("./metadata-pqc/yubico-2026-07-fido-preview-pqc-alpha8.json"))!.AsObject();
            statement["attestationRootCertificates"] = new JsonArray(Convert.ToBase64String(bogusRoot.RawData));
            await File.WriteAllTextAsync(Path.Combine(dir, "alpha8.json"), statement.ToJsonString());

            var metadata = new TestMetadataService([new FileSystemMetadataRepository(dir)]);
            await metadata.InitializeAsync();

            // No policy: the chain does not reach the (bogus) root.
            await Assert.ThrowsAsync<Fido2VerificationException>(() => Verify(response, options, CreateConfig(), metadata));

            // Classical bypass only: does not apply to an ML-DSA attestation certificate.
            await Assert.ThrowsAsync<Fido2VerificationException>(() => Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: true, bypassPostQuantum: false)), metadata));

            // Post-quantum bypass: accepted and reported.
            var result = await Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: false, bypassPostQuantum: true)), metadata);
            Assert.True(result.AttestationChainValidationSkipped);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task NoMetadata_PolicyIsNotReportedAsSkipped()
    {
        if (!CanRunEs256Vector)
            return;

        // Without a metadata statement there are no trust anchors to validate against, so nothing
        // is bypassed by the policy and the credential must not be flagged as skipped.
        var (response, options) = await LoadVectorAsync("Es256");

        var result = await Verify(response, options, CreateConfig(Alpha8Policy(bypassClassical: true, bypassPostQuantum: true)), metadataService: null);

        Assert.False(result.AttestationChainValidationSkipped);
        Assert.Equal("packed", result.AttestationFormat);
    }

    // ---- Helpers -----------------------------------------------------------------------------

    private static Task<RegisteredPublicKeyCredential> Verify(AuthenticatorAttestationResponse response, CredentialCreateOptions options, Fido2Configuration config, IMetadataService metadataService)
    {
        return response.VerifyAsync(options, config, (x, ct) => Task.FromResult(true), metadataService, requestTokenBindingId: null, CancellationToken.None);
    }

    private static async Task<(AuthenticatorAttestationResponse Response, CredentialCreateOptions Options)> LoadVectorAsync(string name)
    {
        var raw = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(await File.ReadAllTextAsync($"./attestationYubicoPqcAlpha8{name}.json"));
        var options = JsonSerializer.Deserialize<CredentialCreateOptions>(await File.ReadAllTextAsync($"./attestationOptionsYubicoPqcAlpha8{name}.json"));
        return (AuthenticatorAttestationResponse.Parse(raw), options);
    }

    private static async Task<TestMetadataService> Alpha8MetadataServiceAsync()
    {
        var service = new TestMetadataService([new FileSystemMetadataRepository("./metadata-pqc")]);
        await service.InitializeAsync();
        return service;
    }

    /// <summary>Wraps a metadata service and reports conformance-testing mode, in which policies must be ignored.</summary>
    private sealed class ConformanceModeMetadataService(IMetadataService inner) : IMetadataService
    {
        public Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default) => inner.GetEntryAsync(aaguid, cancellationToken);

        public bool ConformanceTesting() => true;
    }
}

#pragma warning restore SYSLIB5006
