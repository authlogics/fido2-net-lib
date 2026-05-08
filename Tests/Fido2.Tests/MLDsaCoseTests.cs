using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

using Test;

namespace fido2_net_lib.Test;

public class MLDsaCoseTests
{
    // COSE constant tests

    [Fact]
    public void Algorithm_ML_DSA_44_HasCorrectValue() => Assert.Equal(-48, (int)COSE.Algorithm.ML_DSA_44);

    [Fact]
    public void Algorithm_ML_DSA_65_HasCorrectValue() => Assert.Equal(-49, (int)COSE.Algorithm.ML_DSA_65);

    [Fact]
    public void Algorithm_ML_DSA_87_HasCorrectValue() => Assert.Equal(-50, (int)COSE.Algorithm.ML_DSA_87);

    [Fact]
    public void KeyType_AKP_HasCorrectValue() => Assert.Equal(7, (int)COSE.KeyType.AKP);

    [Fact]
    public void KeyTypeParameter_Pub_HasCorrectValue() => Assert.Equal(-1, (int)COSE.KeyTypeParameter.Pub);

    // Size helper tests

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44, 1312)]
    [InlineData(COSE.Algorithm.ML_DSA_65, 1952)]
    [InlineData(COSE.Algorithm.ML_DSA_87, 2592)]
    public void GetMLDsaPublicKeySize_ReturnsCorrectSize(COSE.Algorithm alg, int expected)
    {
        Assert.Equal(expected, COSE.GetMLDsaPublicKeySize(alg));
    }

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44, 2420)]
    [InlineData(COSE.Algorithm.ML_DSA_65, 3309)]
    [InlineData(COSE.Algorithm.ML_DSA_87, 4627)]
    public void GetMLDsaSignatureSize_ReturnsCorrectSize(COSE.Algorithm alg, int expected)
    {
        Assert.Equal(expected, COSE.GetMLDsaSignatureSize(alg));
    }

    [Fact]
    public void GetMLDsaPublicKeySize_ThrowsForNonMLDsa()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => COSE.GetMLDsaPublicKeySize(COSE.Algorithm.ES256));
    }

    [Fact]
    public void GetMLDsaSignatureSize_ThrowsForNonMLDsa()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => COSE.GetMLDsaSignatureSize(COSE.Algorithm.ES256));
    }

    // AKP parser happy-path tests

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44, 1312)]
    [InlineData(COSE.Algorithm.ML_DSA_65, 1952)]
    [InlineData(COSE.Algorithm.ML_DSA_87, 2592)]
    public void AkpParser_HappyPath(COSE.Algorithm alg, int pubKeySize)
    {
        var pub = new byte[pubKeySize];
        RandomNumberGenerator.Fill(pub);

        var cpk = BuildAkpCborMap(alg, pub);
        var credPk = new CredentialPublicKey(cpk);

        Assert.Equal(COSE.KeyType.AKP, credPk._type);
        Assert.Equal(alg, credPk._alg);
        Assert.Equal(pub, credPk._mldsaPublicKey);
    }

    // AKP parser failure tests

    [Fact]
    public void AkpParser_MissingPub_Throws()
    {
        var cpk = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
            { (long)COSE.KeyCommonParameter.Alg, (long)COSE.Algorithm.ML_DSA_65 }
        };

        Assert.Throws<InvalidOperationException>(() => new CredentialPublicKey(cpk));
    }

    [Fact]
    public void AkpParser_PubNotByteString_Throws()
    {
        var cpk = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
            { (long)COSE.KeyCommonParameter.Alg, (long)COSE.Algorithm.ML_DSA_65 },
            { -1L, "not bytes" }
        };

        Assert.Throws<InvalidOperationException>(() => new CredentialPublicKey(cpk));
    }

    [Fact]
    public void AkpParser_WrongPubLength_Throws()
    {
        var pub = new byte[100]; // wrong size for any ML-DSA
        var cpk = BuildAkpCborMap(COSE.Algorithm.ML_DSA_65, pub);

        Assert.Throws<InvalidOperationException>(() => new CredentialPublicKey(cpk));
    }

    [Fact]
    public void AkpParser_InvalidAlg_ES256_Throws()
    {
        var pub = new byte[1952];
        var cpk = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
            { (long)COSE.KeyCommonParameter.Alg, (long)COSE.Algorithm.ES256 }
        };
        cpk.Add(-1L, pub);

        Assert.Throws<InvalidOperationException>(() => new CredentialPublicKey(cpk));
    }

    [Fact]
    public void Ec2Key_WithMLDsaAlg_Throws()
    {
        // kty=EC2 paired with alg=ML_DSA_65 should throw via the EC2 path
        var cpk = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.EC2 },
            { (long)COSE.KeyCommonParameter.Alg, (long)COSE.Algorithm.ML_DSA_65 }
        };

        Assert.ThrowsAny<Exception>(() => new CredentialPublicKey(cpk));
    }

    // Helper

    private static CborMap BuildAkpCborMap(COSE.Algorithm alg, byte[] pub)
    {
        var cpk = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
            { (long)COSE.KeyCommonParameter.Alg, (long)alg }
        };
        cpk.Add(-1L, pub);
        return cpk;
    }
}

public class PubKeyCredParamMLDsaTests
{
    [Fact]
    public void Defaults_DoesNotContainMLDsa()
    {
        var defaults = PubKeyCredParam.Defaults;
        Assert.DoesNotContain(defaults, p => p.Alg == COSE.Algorithm.ML_DSA_44);
        Assert.DoesNotContain(defaults, p => p.Alg == COSE.Algorithm.ML_DSA_65);
        Assert.DoesNotContain(defaults, p => p.Alg == COSE.Algorithm.ML_DSA_87);
    }

    [Fact]
    public void WithExperimentalMLDsaFirst_FirstIsMLDsa65()
    {
        var list = PubKeyCredParam.WithExperimentalMLDsaFirst();
        Assert.Equal(COSE.Algorithm.ML_DSA_65, list[0].Alg);
    }

    [Fact]
    public void WithExperimentalMLDsaFirst_ContainsClassicalDefaults()
    {
        var list = PubKeyCredParam.WithExperimentalMLDsaFirst();
        Assert.Contains(list, p => p.Alg == COSE.Algorithm.ES256);
        Assert.Contains(list, p => p.Alg == COSE.Algorithm.RS256);
    }
}

#pragma warning disable SYSLIB5006

public class MLDsaVerifierTests
{
    // Mapping tests

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public void Map_ReturnsCorrectMLDsaAlgorithm(COSE.Algorithm alg)
    {
        var result = MLDsaCoseVerifier.Map(alg);
        var expected = alg switch
        {
            COSE.Algorithm.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
            COSE.Algorithm.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
            COSE.Algorithm.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new Exception()
        };
        Assert.Equal(expected, result);
    }

    [Fact]
    public void Map_ThrowsForES256()
    {
        Assert.Throws<NotSupportedException>(() => MLDsaCoseVerifier.Map(COSE.Algorithm.ES256));
    }

    // Crypto round-trip tests

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public void Verify_RoundTrip_ValidSignature(COSE.Algorithm alg)
    {
        if (!MLDsa.IsSupported)
            return; // skip on platforms without ML-DSA support

        var mldsaAlg = MLDsaCoseVerifier.Map(alg);
        using var key = MLDsa.GenerateKey(mldsaAlg);

        var pub = key.ExportMLDsaPublicKey();

        var cpkMap = BuildAkpCborMap(alg, pub);
        var cpk = new CredentialPublicKey(cpkMap);

        byte[] data = RandomNumberGenerator.GetBytes(64);
        byte[] sig = key.SignData(data);

        Assert.True(cpk.Verify(data, sig));
    }

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public void Verify_TamperedData_ReturnsFalse(COSE.Algorithm alg)
    {
        if (!MLDsa.IsSupported)
            return;

        var mldsaAlg = MLDsaCoseVerifier.Map(alg);
        using var key = MLDsa.GenerateKey(mldsaAlg);

        var pub = key.ExportMLDsaPublicKey();
        var cpk = new CredentialPublicKey(BuildAkpCborMap(alg, pub));

        byte[] data = RandomNumberGenerator.GetBytes(64);
        byte[] sig = key.SignData(data);

        // Flip a byte in data
        data[0] ^= 0xFF;
        Assert.False(cpk.Verify(data, sig));
    }

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public void Verify_TamperedSignature_ReturnsFalse(COSE.Algorithm alg)
    {
        if (!MLDsa.IsSupported)
            return;

        var mldsaAlg = MLDsaCoseVerifier.Map(alg);
        using var key = MLDsa.GenerateKey(mldsaAlg);

        var pub = key.ExportMLDsaPublicKey();
        var cpk = new CredentialPublicKey(BuildAkpCborMap(alg, pub));

        byte[] data = RandomNumberGenerator.GetBytes(64);
        byte[] sig = key.SignData(data);

        // Flip a byte in signature
        sig[0] ^= 0xFF;
        Assert.False(cpk.Verify(data, sig));
    }

    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public void Verify_TruncatedSignature_ReturnsFalse(COSE.Algorithm alg)
    {
        if (!MLDsa.IsSupported)
            return;

        var mldsaAlg = MLDsaCoseVerifier.Map(alg);
        using var key = MLDsa.GenerateKey(mldsaAlg);

        var pub = key.ExportMLDsaPublicKey();
        var cpk = new CredentialPublicKey(BuildAkpCborMap(alg, pub));

        byte[] data = RandomNumberGenerator.GetBytes(64);
        byte[] sig = key.SignData(data);

        // Truncate signature by one byte
        byte[] truncated = sig[..^1];
        Assert.False(cpk.Verify(data, truncated));
    }

    private static CborMap BuildAkpCborMap(COSE.Algorithm alg, byte[] pub)
    {
        var cpk = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
            { (long)COSE.KeyCommonParameter.Alg, (long)alg }
        };
        cpk.Add(-1L, pub);
        return cpk;
    }
}

/// <summary>
/// End-to-end assertion tests for ML-DSA: generates an ML-DSA key, builds
/// attested credential data, synthesises an assertion, and validates it
/// through the public Fido2.MakeAssertionAsync API.
/// </summary>
public class MLDsaEndToEndTests
{
    [Theory]
    [InlineData(COSE.Algorithm.ML_DSA_44)]
    [InlineData(COSE.Algorithm.ML_DSA_65)]
    [InlineData(COSE.Algorithm.ML_DSA_87)]
    public async Task AssertionRoundTrip_WithMLDsa_Succeeds(COSE.Algorithm alg)
    {
        if (!MLDsa.IsSupported)
            return;

        var mldsaAlg = MLDsaCoseVerifier.Map(alg);
        using var key = MLDsa.GenerateKey(mldsaAlg);
        var pub = key.ExportMLDsaPublicKey();

        var cpkMap = new CborMap
        {
            { (long)COSE.KeyCommonParameter.KeyType, (long)COSE.KeyType.AKP },
            { (long)COSE.KeyCommonParameter.Alg, (long)alg }
        };
        cpkMap.Add(-1L, pub);
        var cpk = new CredentialPublicKey(cpkMap);

        const string rp = "https://www.passwordless.dev";
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rp));
        var flags = AuthenticatorFlags.AT | AuthenticatorFlags.ED | AuthenticatorFlags.UP | AuthenticatorFlags.UV;
        var aaGuid = new Guid("F1D0F1D0-F1D0-F1D0-F1D0-F1D0F1D0F1D0");
        var credentialId = new byte[] { 0xf1, 0xd0 };

        var acd = new AttestedCredentialData(aaGuid, credentialId, cpk);
        var extBytes = new CborMap { { "testing", true } }.Encode();
        var exts = new Extensions(extBytes);
        var ad = new AuthenticatorData(rpIdHash, flags, 1, acd, exts);
        var authData = ad.ToByteArray();

        var challenge = RandomNumberGenerator.GetBytes(128);
        var clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.get",
            Challenge = challenge,
            Origin = rp
        });

        var hashedClientDataJson = SHA256.HashData(clientDataJson);
        byte[] data = [.. authData, .. hashedClientDataJson];
        byte[] signature = key.SignData(data);

        var lib = new Fido2(new Fido2Configuration
        {
            ServerDomain = rp,
            ServerName = rp,
            Origins = new HashSet<string> { rp },
        });

        var existingCredentials = new List<PublicKeyCredentialDescriptor> { new(credentialId) };
        var options = lib.GetAssertionOptions(existingCredentials, null, null);
        options.Challenge = challenge;

        var response = new AuthenticatorAssertionRawResponse
        {
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = RandomNumberGenerator.GetBytes(16),
            },
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = credentialId,
        };

        var result = await lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = cpk.GetBytes(),
            IsUserHandleOwnerOfCredentialIdCallback = (args, ct) => Task.FromResult(true),
            StoredSignatureCounter = 0
        });

        Assert.Equal(credentialId, result.CredentialId);
        Assert.Equal("1", result.SignCount.ToString("X"));
    }
}

#pragma warning restore SYSLIB5006
