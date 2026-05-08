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

`WithExperimentalMLDsaFirst()` returns a list that prefers **ML-DSA-65**,
followed by the classical defaults (EdDSA, ES256, RS256, PS256, etc.).

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

## References

- [IANA COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml)
- [.NET 10 `MLDsa` API](https://learn.microsoft.com/dotnet/api/system.security.cryptography.mldsa?view=net-10.0)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
