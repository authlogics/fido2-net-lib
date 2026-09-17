# ML-DSA (Post-Quantum) Support

> **⚠️ Experimental** — ML-DSA support is opt-in and relies on the
> `System.Security.Cryptography.MLDsa` API introduced in .NET 10, which is
> marked `[Experimental("SYSLIB5006")]`. Browser and authenticator support
> for ML-DSA in WebAuthn is currently sparse.

## Supported COSE algorithms

| COSE alg value | Name | NIST level | Public key size | Signature size |
|---:|---|---|---:|---:|
| `-48` | ML-DSA-44 | 2 | 1 312 B | 2 420 B |
| `-49` | ML-DSA-65 | 3 | 1 952 B | 3 309 B |
| `-50` | ML-DSA-87 | 5 | 2 592 B | 4 627 B |

COSE key type: `AKP` (`kty = 7`), with the raw FIPS 204 public key in
parameter label `-1` (`pub`).

## Runtime requirements

- **.NET 10** or later.
- A platform cryptographic provider that supports ML-DSA
  (`MLDsa.IsSupported == true`).

If `MLDsa.IsSupported` is `false`, attempting to verify an ML-DSA
signature will throw `PlatformNotSupportedException`.

## Opting in

ML-DSA algorithms are **not** included in the default `pubKeyCredParams`
list. To advertise ML-DSA support to authenticators during registration,
use the provided helper:

```csharp
#pragma warning disable SYSLIB5006 // MLDsa is experimental

var options = fido2.RequestNewCredential(new RequestNewCredentialParams
{
    User = user,
    PubKeyCredParams = PubKeyCredParam.WithExperimentalMLDsaFirst(),
    // ... other parameters
});

#pragma warning restore SYSLIB5006
```

`WithExperimentalMLDsaFirst()` returns a list that places the three ML-DSA
parameter sets first in COSE-identifier order (**ML-DSA-44**, **ML-DSA-65**,
**ML-DSA-87**), followed by the classical defaults (EdDSA, ES256, RS256,
PS256, etc.). Callers that want a different preference between the ML-DSA
parameter sets should supply their own ordered list.

Individual constants are also available for custom lists:

- `PubKeyCredParam.ML_DSA_44`
- `PubKeyCredParam.ML_DSA_65`
- `PubKeyCredParam.ML_DSA_87`

## How it works

- **Registration**: When an authenticator returns an attested credential
  with `kty = AKP`, the library parses the COSE public key and validates
  the `pub` byte string length against the declared algorithm.
- **Assertion**: `CredentialPublicKey.Verify` dispatches to
  `MLDsa.ImportMLDsaPublicKey` + `MLDsa.VerifyData` using raw FIPS 204
  bytes directly from the COSE key. No JWK or SPKI conversion is
  performed in the WebAuthn path.
- **Default behaviour is unchanged**: Relying Parties that do not
  explicitly include ML-DSA in `pubKeyCredParams` will never encounter
  ML-DSA keys.

## Attestation certificates and trust anchors

- Packed attestation statements whose x5c leaf certificate holds an ML-DSA key
  (X.509 algorithm identifiers `2.16.840.1.101.3.4.3.17/18/19`) are supported:
  the attestation public key is built from the certificate and the signature is
  verified as ML-DSA. The certificate's parameter set must match the statement's
  `alg`.
- The certificate chain is validated against the `attestationRootCertificates`
  of the authenticator's metadata statement, exactly as for classical keys.
  Chain building for ML-DSA certificates relies on the OS (`X509Chain`).

### Attestation trust policies (opt-out of chain validation)

For pilots where a manufacturer's attestation CA is not yet available, a Relying
Party can skip trust anchor validation for one authenticator model, separately
for classical (ECDSA/RSA/EdDSA) and post-quantum (ML-DSA) attestation
certificates. The attestation signature is still verified; only the chain to a
trusted root is not. Policies are ignored while conformance testing.

```csharp
var config = new Fido2Configuration
{
    // ...
    AttestationTrustPolicies =
    [
        new AttestationTrustPolicy
        {
            AaGuid = new Guid("2165deef-e5a8-4efa-9fe7-fea9ddb2d227"),
            BypassClassicalChainValidation = true,
            BypassPostQuantumChainValidation = false
        }
    ]
};
```

`RegisteredPublicKeyCredential.AttestationChainValidationSkipped` reports when a
policy applied, so the Relying Party can record or display it.

## References

- [IANA COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml)
- [.NET 10 `MLDsa` API](https://learn.microsoft.com/dotnet/api/system.security.cryptography.mldsa?view=net-10.0)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
