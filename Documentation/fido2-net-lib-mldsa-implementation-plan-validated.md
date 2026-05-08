# Implementation Plan: ML-DSA COSE Algorithm Support for `passwordless-lib/fido2-net-lib`

## Goal

Add relying-party support for COSE algorithm identifiers:

| COSE alg | Name | ML-DSA parameter set |
|---:|---|---|
| `-48` | `ML-DSA-44` | NIST/FIPS 204 level 2 |
| `-49` | `ML-DSA-65` | NIST/FIPS 204 level 3 |
| `-50` | `ML-DSA-87` | NIST/FIPS 204 level 5 |

The RP should be able to:

1. Advertise ML-DSA algorithms in `pubKeyCredParams` when explicitly enabled.
2. Parse ML-DSA COSE public keys using COSE `kty = AKP`.
3. Store ML-DSA credential public keys in the existing credential storage model.
4. Verify WebAuthn assertions using .NET 10 `System.Security.Cryptography.MLDsa` where supported.
5. Preserve existing behaviour for ES256, EdDSA, RSA, and other currently supported algorithms.

References:

- Repository: <https://github.com/passwordless-lib/fido2-net-lib>
- IANA COSE Algorithms registry: <https://www.iana.org/assignments/cose/cose.xhtml>
- .NET 10 ML-DSA API: <https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.mldsa?view=net-10.0>
- .NET 10 PQC libraries overview: <https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/libraries#post-quantum-cryptography-pqc>
- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/>
- CTAP unsupported algorithm behaviour: <https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html>

---

## Important constraints

- Treat this as experimental/opt-in. Browser and authenticator support for ML-DSA WebAuthn credentials may be sparse.
- Do not remove or deprioritise stable classical defaults such as ES256 unless a caller explicitly asks for an ML-DSA-only policy.
- Do not implement ML-DSA primitives manually.
- Use .NET 10 `System.Security.Cryptography.MLDsa` as the preferred verifier.
- Guard runtime use with platform capability checks because .NET 10 ML-DSA depends on underlying platform/provider support.
- The library should fail cleanly with `NotSupportedException`, validation failure, or the project’s existing exception type when ML-DSA is requested but unavailable.

---

## COSE shape to support

Expected credential public key CBOR map:

```cbor
{
  1: 7,        // kty: AKP
  3: -49,      // alg: ML-DSA-65; also allow -48 and -50
 -1: h'...'    // pub: raw ML-DSA public key bytes
}
```

COSE constants:

```text
kty = 1
alg = 3
AKP = 7
pub = -1
priv = -2 // not needed for RP verification, but reserve/define if the codebase models all AKP params
```

Expected raw public key sizes:

| Algorithm | COSE alg | Public key size | Signature size |
|---|---:|---:|---:|
| ML-DSA-44 | `-48` | 1312 bytes | 2420 bytes |
| ML-DSA-65 | `-49` | 1952 bytes | 3309 bytes |
| ML-DSA-87 | `-50` | 2592 bytes | 4627 bytes |

---

## High-level design

Introduce a small signature-verifier abstraction if the repo does not already have one. The goal is to avoid spreading algorithm-specific code through the assertion validator.

Suggested interface:

```csharp
internal interface ICoseSignatureVerifier
{
    bool Supports(COSE.Algorithm algorithm, COSE.KeyType keyType);

    bool Verify(
        COSE.Algorithm algorithm,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signedData,
        ReadOnlySpan<byte> signature);
}
```

For ML-DSA:

```csharp
internal sealed class MLDsaCoseSignatureVerifier : ICoseSignatureVerifier
{
    public bool Supports(COSE.Algorithm algorithm, COSE.KeyType keyType)
        => keyType == COSE.KeyType.AKP && algorithm is
            COSE.Algorithm.ML_DSA_44 or
            COSE.Algorithm.ML_DSA_65 or
            COSE.Algorithm.ML_DSA_87;

    public bool Verify(
        COSE.Algorithm algorithm,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signedData,
        ReadOnlySpan<byte> signature)
    {
#if NET10_0_OR_GREATER
        var mldsaAlgorithm = ToMldsaAlgorithm(algorithm);

        ValidateSizes(algorithm, publicKey, signature);

        using var verifier = MLDsa.ImportMLDsaPublicKey(mldsaAlgorithm, publicKey);
        return verifier.VerifyData(signedData, signature, context: null);
#else
        throw new NotSupportedException("ML-DSA verification requires .NET 10 or a configured external verifier.");
#endif
    }
}
```

Confirm exact import method names and overload signatures against the target SDK used by the repository. The .NET 10 ML-DSA API is marked experimental, so expect `SYSLIB5006` warnings and decide whether to suppress them in the smallest possible scope.

---

## Step-by-step implementation

### 1. Create a feature branch

```bash
git checkout -b feature/cose-mldsa-webauthn
```

Run the existing test suite before changes:

```bash
dotnet test
```

Record any pre-existing failures separately.

---

### 2. Locate the existing COSE model

Search for these types and files:

```bash
rg "enum Algorithm|COSE.Algorithm|KeyType|COSE.KeyType|PubKeyCredParams|CredentialPublicKey|PublicKeyCredentialParameters" Src Tests
```

Likely areas:

- COSE algorithm enum
- COSE key type enum
- COSE key parameter enum/constants
- credential public key parser
- assertion signature verifier
- registration options / `pubKeyCredParams` generation
- tests for COSE key parsing and assertion verification

Do not assume exact file names; follow the current structure of the repository.

---

### 3. Add COSE algorithm constants

Add enum values:

```csharp
ML_DSA_44 = -48,
ML_DSA_65 = -49,
ML_DSA_87 = -50,
```

If the enum uses `EnumMember` attributes or JSON conversion names, add names matching the existing style. Suggested names:

```csharp
[EnumMember(Value = "ML-DSA-44")]
ML_DSA_44 = -48,

[EnumMember(Value = "ML-DSA-65")]
ML_DSA_65 = -49,

[EnumMember(Value = "ML-DSA-87")]
ML_DSA_87 = -50,
```

Acceptance criteria:

- The enum serialises/deserialises consistently with existing algorithm values.
- Existing algorithms retain current numeric values and public API names.

---

### 4. Add COSE AKP key type support

Add:

```csharp
AKP = 7
```

If the codebase has key parameter enums/constants, add:

```csharp
Pub = -1
Priv = -2 // optional; RP normally only uses Pub
```

Acceptance criteria:

- Parser recognises `kty = 7` as AKP.
- Unknown key types still fail exactly as before.

---

### 5. Extend credential public key parsing

For AKP keys:

1. Require `kty = AKP`.
2. Require `alg` to be one of `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`.
3. Require `pub` parameter `-1` to be present.
4. Require `pub` to be a byte string.
5. Reject private key material if the parser currently rejects unexpected fields; otherwise ignore `priv = -2` for RP use.
6. Validate public key length for the algorithm.

Suggested size helper:

```csharp
internal static int GetMLDsaPublicKeySize(COSE.Algorithm alg) => alg switch
{
    COSE.Algorithm.ML_DSA_44 => 1312,
    COSE.Algorithm.ML_DSA_65 => 1952,
    COSE.Algorithm.ML_DSA_87 => 2592,
    _ => throw new ArgumentOutOfRangeException(nameof(alg), alg, null)
};

internal static int GetMLDsaSignatureSize(COSE.Algorithm alg) => alg switch
{
    COSE.Algorithm.ML_DSA_44 => 2420,
    COSE.Algorithm.ML_DSA_65 => 3309,
    COSE.Algorithm.ML_DSA_87 => 4627,
    _ => throw new ArgumentOutOfRangeException(nameof(alg), alg, null)
};
```

Acceptance criteria:

- Well-formed AKP/ML-DSA COSE keys parse successfully.
- Wrong `alg`/`kty` combinations fail.
- Missing `pub` fails.
- Wrong public key length fails.
- Existing EC2/OKP/RSA parsing is unaffected.

---

### 6. Add verifier abstraction or extend the existing verification dispatch

Prefer adding/using a verifier registry rather than embedding ML-DSA directly in a large switch.

Suggested dispatch logic:

```csharp
var verifier = verifiers.SingleOrDefault(v => v.Supports(algorithm, keyType));
if (verifier is null)
{
    throw new NotSupportedException($"Unsupported COSE algorithm/key type combination: {algorithm}/{keyType}");
}

var verified = verifier.Verify(algorithm, publicKeyBytes, signedData, signature);
```

For WebAuthn assertions, `signedData` must remain:

```text
authenticatorData || SHA256(clientDataJSON)
```

Do not pre-hash this value for ML-DSA unless a future WebAuthn/COSE profile explicitly requires different behaviour. The .NET API method to use is `VerifyData`, not `VerifyHash`.

Acceptance criteria:

- Existing assertion verification tests pass.
- Signature verification dispatch is deterministic and easy to extend.
- Unsupported algorithms produce a clear failure.

---

### 7. Add .NET 10 ML-DSA verifier

Target .NET 10 with conditional compilation if the library multi-targets older frameworks.

Example skeleton:

```csharp
#if NET10_0_OR_GREATER
using System.Security.Cryptography;
#endif

internal sealed class MLDsaCoseSignatureVerifier : ICoseSignatureVerifier
{
    public bool Supports(COSE.Algorithm algorithm, COSE.KeyType keyType)
        => keyType == COSE.KeyType.AKP && algorithm is
            COSE.Algorithm.ML_DSA_44 or
            COSE.Algorithm.ML_DSA_65 or
            COSE.Algorithm.ML_DSA_87;

    public bool Verify(
        COSE.Algorithm algorithm,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signedData,
        ReadOnlySpan<byte> signature)
    {
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
        var mldsaAlgorithm = algorithm switch
        {
            COSE.Algorithm.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
            COSE.Algorithm.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
            COSE.Algorithm.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new NotSupportedException($"Unsupported ML-DSA algorithm: {algorithm}")
        };

        ValidateSizes(algorithm, publicKey, signature);

        if (!MLDsa.IsSupported)
        {
            throw new PlatformNotSupportedException("ML-DSA is not supported by this .NET/platform cryptographic provider.");
        }

        using var key = MLDsa.ImportMLDsaPublicKey(mldsaAlgorithm, publicKey);
        return key.VerifyData(signedData, signature, context: null);
#pragma warning restore SYSLIB5006
#else
        throw new PlatformNotSupportedException("ML-DSA verification requires .NET 10 or later.");
#endif
    }
}
```

Notes for the coding agent:

- Confirm `MLDsa.IsSupported` availability and exact signature in the SDK version used.
- Confirm whether `ImportMLDsaPublicKey` accepts `ReadOnlySpan<byte>` directly or requires an array.
- Keep warning suppression local to ML-DSA code only.
- Add an internal seam for tests if CI cannot guarantee ML-DSA platform support.

Acceptance criteria:

- On .NET 10 with ML-DSA support, valid signatures verify.
- Invalid signatures fail.
- Unsupported platforms skip ML-DSA crypto tests or assert the expected platform exception.
- Older target frameworks compile without referencing unavailable APIs.

---

### 8. Add opt-in RP configuration

Do not add ML-DSA to the default `pubKeyCredParams` unless maintainers explicitly want that.

Preferred approach:

```csharp
options.PubKeyCredParams = new[]
{
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.ML_DSA_65),
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.ES256),
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.EdDSA),
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.RS256),
};
```

If the repo has configuration helpers, add an explicit setting such as:

```csharp
public bool EnableExperimentalMLDsaAlgorithms { get; init; }
```

or a named helper:

```csharp
public static IReadOnlyList<PublicKeyCredentialParameters> WithExperimentalMLDsaFirst()
```

Ordering guidance:

- If testing ML-DSA, put `-49` or the desired ML-DSA algorithm first.
- Include ES256 and other stable algorithms after it for real deployments.
- If no authenticator supports any advertised algorithm, registration fails with unsupported algorithm behaviour.

Acceptance criteria:

- Existing default registration options are unchanged unless explicitly configured.
- Callers can opt into `-48`, `-49`, and/or `-50`.
- Documentation warns about limited ecosystem support.

---

### 9. Registration ceremony handling

During attestation/registration validation:

1. Parse the authenticator data and embedded COSE credential public key.
2. Accept AKP/ML-DSA public keys only if the algorithm was offered by the RP in `pubKeyCredParams` or otherwise allowed by current policy.
3. Persist the raw credential public key bytes exactly as parsed.
4. Persist algorithm metadata if the repo already stores or exposes it.

Acceptance criteria:

- ML-DSA credential registration succeeds with a valid attestation object containing AKP key material.
- A credential using `alg = -49` is rejected if the RP policy did not allow `-49`.
- Existing attestation formats continue to work.

---

### 10. Assertion ceremony handling

During assertion validation:

1. Retrieve the stored credential public key.
2. Parse `kty`, `alg`, and public key bytes.
3. Build WebAuthn signed data exactly as before:

```text
authenticatorData || SHA256(clientDataJSON)
```

4. Dispatch to the ML-DSA verifier for AKP/ML-DSA.
5. Preserve sign-counter, user-presence, user-verification, challenge, RP ID hash, and origin checks unchanged.

Acceptance criteria:

- Valid ML-DSA assertion verifies.
- Tampered `authenticatorData`, `clientDataJSON`, or signature fails.
- Existing assertion tests for classical algorithms still pass.

---

### 11. Tests to add

#### Unit tests: COSE constants

- `Algorithm.ML_DSA_44` equals `-48`.
- `Algorithm.ML_DSA_65` equals `-49`.
- `Algorithm.ML_DSA_87` equals `-50`.
- `KeyType.AKP` equals `7`.

#### Unit tests: AKP parser

Create CBOR maps for each algorithm:

```cbor
{ 1: 7, 3: -48, -1: bytes(1312) }
{ 1: 7, 3: -49, -1: bytes(1952) }
{ 1: 7, 3: -50, -1: bytes(2592) }
```

Test failures:

- Missing `-1`.
- `-1` is not a byte string.
- Wrong public key length.
- `kty = EC2` with `alg = -49`.
- `kty = AKP` with non-ML-DSA algorithm.

#### Unit tests: verifier mapping

- `-48` maps to `MLDsa44`.
- `-49` maps to `MLDsa65`.
- `-50` maps to `MLDsa87`.
- Unsupported values throw.

#### Crypto tests: .NET 10 only

Use generated keys when platform supports ML-DSA:

1. Generate or import test key pair.
2. Sign deterministic test data with `MLDsa.SignData`.
3. Verify with `MLDsaCoseSignatureVerifier`.
4. Modify one byte of data and assert verification fails.
5. Modify one byte of signature and assert verification fails.

Skip or assert platform exception when `MLDsa.IsSupported == false`.

#### Integration tests: WebAuthn assertion path

If full authenticator fixture generation is practical:

- Add an ML-DSA credential public key fixture.
- Add a synthetic assertion signed with the matching private key.
- Validate through the public assertion API.

If full fixture generation is not practical:

- Add a narrower test at the point where parsed credential public key + signed bytes + signature are passed to the verifier.

---

### 12. Documentation updates

Add a short documentation page or section:

```markdown
## Experimental ML-DSA / post-quantum WebAuthn support

The library can parse and verify COSE AKP public keys for ML-DSA algorithms:

- ML-DSA-44 / COSE alg -48
- ML-DSA-65 / COSE alg -49
- ML-DSA-87 / COSE alg -50

This requires .NET 10 and platform cryptographic provider support for `System.Security.Cryptography.MLDsa`.

This support is experimental because browser/authenticator support is not yet broadly deployed. Keep ES256 or other established algorithms in `pubKeyCredParams` for production compatibility.
```

Also update any algorithm support matrix.

---

### 13. CI and target framework handling

Check the repository target frameworks.

If it already targets .NET 10:

- Add ML-DSA tests under the .NET 10 test target.
- Use runtime skip conditions for unsupported crypto providers.

If it does not target .NET 10:

- Add `net10.0` as an additional target only if maintainers are comfortable.
- Otherwise add interfaces and COSE parsing now, with .NET 10 verifier in a separate package or future branch.

Suggested conditional item group:

```xml
<TargetFrameworks>net8.0;net10.0</TargetFrameworks>
```

Only add this after checking the repo’s current support policy.

---

### 14. Security review checklist

- No hand-written ML-DSA primitive implementation.
- Reject malformed COSE keys early.
- Enforce algorithm/key type consistency.
- Enforce public key and signature lengths before crypto provider call.
- Preserve challenge, origin, RP ID hash, UV/UP, sign counter, and extension checks.
- Do not treat ML-DSA credentials as interchangeable with EdDSA or ECDSA credentials.
- Do not silently downgrade from ML-DSA verification to another algorithm.
- Do not enable ML-DSA by default until project maintainers choose that policy.

---

## Suggested PR breakdown

### PR 1: COSE model and parser

- Add `Algorithm` enum values.
- Add `KeyType.AKP`.
- Add AKP public key parser.
- Add parser tests.
- No cryptographic verification yet.

### PR 2: Verifier abstraction

- Introduce or refactor signature verification dispatch.
- Move existing algorithm verification behind the abstraction.
- Ensure all existing tests pass.

### PR 3: .NET 10 ML-DSA verifier

- Add `MLDsaCoseSignatureVerifier`.
- Add .NET 10 conditional compilation.
- Add crypto tests with platform skip.

### PR 4: RP opt-in configuration and docs

- Add explicit configuration helper or documented `pubKeyCredParams` guidance.
- Add docs and examples.
- Add release-note entry.

---

## Definition of done

- `dotnet test` passes for existing targets.
- `net10.0` ML-DSA tests pass on a platform where `MLDsa.IsSupported` is true.
- Unsupported platforms fail gracefully or skip ML-DSA tests.
- Existing WebAuthn registration and assertion behaviour is unchanged by default.
- ML-DSA can be explicitly advertised in `pubKeyCredParams`.
- AKP/ML-DSA public keys parse and validate correctly.
- ML-DSA signatures verify using .NET 10 built-in cryptography.
- Documentation clearly marks the feature as experimental/opt-in.

---

## Validation against `swissbit-eis/SimpleWebAuthn` `mldsa_support`

Validation date: 2026-05-08

Reference implementation reviewed:

- Repository: <https://github.com/swissbit-eis/SimpleWebAuthn/tree/mldsa_support>
- Commit: `8d2ec16` — `Add support for ML-DSA`
- Commit: `4c5a7b7` — `example project prefers ML-DSA-65`

### Result

The implementation plan is broadly aligned with the independent SimpleWebAuthn RP implementation. The main design points are validated:

- Add COSE algorithm identifiers `-48`, `-49`, and `-50`.
- Add COSE `AKP = 7`.
- Add AKP public-key parameter `pub = -1`.
- Dispatch AKP keys to a dedicated ML-DSA verifier.
- Verify the WebAuthn signed bytes directly, without adding an extra hash/pre-hash layer.
- Put ML-DSA in `pubKeyCredParams` only when explicitly requested or configured.
- Prefer `ML-DSA-65` (`-49`) first in examples when testing ML-DSA, with classical algorithms retained as fallback.

### SimpleWebAuthn design details to mirror conceptually

SimpleWebAuthn’s ML-DSA branch makes these changes:

1. Adds `COSEPublicKeyAKP`, `isCOSEPublicKeyAKP`, `COSEKTY.AKP = 7`, `COSEKEYS.pub = -1`, and `COSEALG.MLDSA44/-65/-87 = -48/-49/-50`.
2. Maps COSE algorithms to provider names: `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`.
3. Extends verification dispatch from EC2/RSA/OKP to include AKP.
4. Adds a dedicated `verifyAKP()` function.
5. In `verifyAKP()`, validates:
   - `kty === AKP`
   - `alg` exists
   - `alg` is a known COSE algorithm
   - `alg` is one of `MLDSA44`, `MLDSA65`, `MLDSA87`
   - `pub` exists
6. Imports AKP public key material as JWK-like key data:
   - `kty: 'AKP'`
   - `alg: 'ML-DSA-*'`
   - `pub: base64url(pub)`
   - `ext: false`
7. Calls WebCrypto `subtle.verify({ name }, key, signature, data)`.
8. Adds `-48`, `-49`, and `-50` to registration supported algorithm identifiers.
9. Updates the example project to prefer `[-49, -7, -257]`.
10. Raises the Node engine requirement to `>=24.14.0` because its verifier depends on Node WebCrypto ML-DSA support.

### Recommended adjustments to the .NET plan

#### 1. Keep the feature opt-in by default

The original plan says not to add ML-DSA to default `pubKeyCredParams` unless maintainers choose that policy. Keep this. SimpleWebAuthn added ML-DSA to its internal supported identifiers, but the example only requests it explicitly via `supportedAlgorithmIDs: [-49, -7, -257]`. For `fido2-net-lib`, preserve the existing default registration behaviour unless a caller opts in.

#### 2. Match SimpleWebAuthn's verification dispatch shape

SimpleWebAuthn added a dedicated AKP verifier rather than mixing AKP into EC2/OKP/RSA verification. In `fido2-net-lib`, implement the equivalent as either:

- `MLDsaCoseSignatureVerifier`, if adding a verifier abstraction; or
- a focused AKP/ML-DSA branch in the existing assertion verifier.

Do not spread ML-DSA special cases across registration and assertion validation.

#### 3. Validate `alg` and `pub` before provider import

The original plan already includes this, but the validation priority should be explicit:

1. `kty == AKP`
2. `alg` is present
3. `alg` is one of `-48/-49/-50`
4. `pub` is present and is a byte string
5. `pub` length matches the selected ML-DSA parameter set
6. signature length matches the selected ML-DSA parameter set

SimpleWebAuthn validates presence and algorithm compatibility before importing into WebCrypto. The .NET implementation should do the same before calling `MLDsa.ImportMLDsaPublicKey()`.

#### 4. Use .NET raw FIPS 204 public-key import, not JWK/SPKI

SimpleWebAuthn has to construct AKP key data for WebCrypto. The .NET plan should not copy that representation internally. For .NET 10, import the COSE `pub` bytes directly with:

```csharp
using var key = MLDsa.ImportMLDsaPublicKey(mldsaAlgorithm, publicKey);
```

Only use SPKI/PEM APIs for test fixtures or interop utilities; the WebAuthn COSE AKP path should use the raw `pub` bytes.

#### 5. Preserve direct message verification

SimpleWebAuthn passes `data` directly to `subtle.verify()`. The .NET plan should continue using `VerifyData(signedData, signature, context: ReadOnlySpan<byte>.Empty)` or the exact available overload for the selected SDK. Do not use `VerifyHash`, `VerifyMu`, or `VerifyPreHash` for WebAuthn assertion data unless a later COSE/WebAuthn profile mandates it.

#### 6. Add provider capability checks equivalent to SimpleWebAuthn's engine gate

SimpleWebAuthn raises the Node engine requirement to `>=24.14.0`. The .NET equivalent is not a package-wide runtime bump by default; instead:

- Multi-target `net10.0` for the built-in verifier.
- Use `MLDsa.IsSupported` at runtime.
- On unsupported targets or providers, fail clearly or skip crypto tests.

#### 7. Prefer ML-DSA-65 in examples

Update examples/docs to show:

```csharp
options.PubKeyCredParams = new[]
{
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.ML_DSA_65),
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.ES256),
    new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, COSE.Algorithm.RS256),
};
```

This mirrors SimpleWebAuthn’s example preference order `[-49, -7, -257]`.

### Additional acceptance criteria from validation

Add these to the Definition of Done:

- AKP verification code is isolated in one verifier/dispatch branch.
- ML-DSA registration examples prefer `-49` but retain classical fallback algorithms.
- The raw COSE `pub` byte string is imported as a FIPS 204 ML-DSA public key in .NET 10.
- No JWK/SPKI conversion is introduced in the normal WebAuthn assertion path.
- Tests cover missing `alg`, invalid `alg`, unsupported AKP algorithm, and missing `pub`, matching the validation behaviour seen in SimpleWebAuthn.

### Plan status after validation

No major rewrite required. Apply the recommended adjustments above before handing this to a coding agent.
