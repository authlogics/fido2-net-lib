#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

using System;
using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal static class MLDsaCoseVerifier
{
    public static bool IsSupported => MLDsa.IsSupported;

    public static MLDsaAlgorithm Map(COSE.Algorithm alg) => alg switch
    {
        COSE.Algorithm.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
        COSE.Algorithm.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
        COSE.Algorithm.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new NotSupportedException($"Unsupported ML-DSA algorithm: {alg}")
    };

    public static bool Verify(
        COSE.Algorithm alg,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        if (signature.Length != COSE.GetMLDsaSignatureSize(alg))
            return false;

        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException(
                "ML-DSA is not supported by this platform's cryptographic provider.");

        using var key = MLDsa.ImportMLDsaPublicKey(Map(alg), publicKey);
        return key.VerifyData(data, signature, context: ReadOnlySpan<byte>.Empty);
    }
}

#pragma warning restore SYSLIB5006
