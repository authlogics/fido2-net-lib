using System.Security.Cryptography;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

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

#pragma warning restore SYSLIB5006
