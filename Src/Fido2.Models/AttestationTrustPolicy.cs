namespace Fido2NetLib;

/// <summary>
/// Per-authenticator override of attestation certificate chain validation.
/// </summary>
/// <remarks>
/// By default every attestation statement carrying an x5c certificate chain is validated against the
/// trust anchors of the authenticator's metadata statement. A policy lets a Relying Party skip that
/// validation for one authenticator model (AAGUID), separately for attestation certificates with
/// classical keys (ECDSA, RSA, EdDSA) and with post-quantum keys (ML-DSA). This is intended for
/// pilots and test deployments where a manufacturer's attestation CA is not yet available; the
/// attestation signature itself is still verified, only the chain to a trusted root is not.
/// Policies are ignored while conformance testing.
/// </remarks>
public sealed class AttestationTrustPolicy
{
    /// <summary>
    /// The AAGUID of the authenticator model the policy applies to.
    /// </summary>
    public Guid AaGuid { get; set; }

    /// <summary>
    /// Skip trust anchor validation when the attestation certificate uses a classical key (ECDSA, RSA, EdDSA).
    /// </summary>
    public bool BypassClassicalChainValidation { get; set; }

    /// <summary>
    /// Skip trust anchor validation when the attestation certificate uses a post-quantum key (ML-DSA).
    /// </summary>
    public bool BypassPostQuantumChainValidation { get; set; }
}
