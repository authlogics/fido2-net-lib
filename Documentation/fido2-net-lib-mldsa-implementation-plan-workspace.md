# ML-DSA (Post-Quantum) Implementation Plan — `authlogics/fido2-net-lib` Workspace

> Companion to `fido2-net-lib-mldsa-implementation-plan-validated.md`.
> This document is **workspace-specific**: it maps the generic plan onto the
> actual files, types, and conventions present in this repository on branch
> `feature/ml-dsa`.

---

## 1. Goal

Add Relying-Party support for the COSE/FIPS 204 ML-DSA algorithms:

| COSE alg | Name | Parameter set | Public key | Signature |
|---:|---|---|---:|---:|
| `-48` | `ML-DSA-44` | NIST level 2 | 1312 B | 2420 B |
| `-49` | `ML-DSA-65` | NIST level 3 | 1952 B | 3309 B |
| `-50` | `ML-DSA-87` | NIST level 5 | 2592 B | 4627 B |

Capabilities to deliver:

1. Parse ML-DSA COSE public keys (`kty = AKP = 7`, `pub = -1`).
2. Verify WebAuthn assertions signed with ML-DSA using
   `System.Security.Cryptography.MLDsa` (.NET 10).
3. Allow Relying Parties to **opt in** to advertising `-48`/`-49`/`-50`
   in `pubKeyCredParams`.
4. Preserve the existing default behaviour for ES256, EdDSA, RSA, etc.

References:

- IANA COSE registry: <https://www.iana.org/assignments/cose/cose.xhtml>
- .NET 10 `MLDsa` API: <https://learn.microsoft.com/dotnet/api/system.security.cryptography.mldsa?view=net-10.0>
- WebAuthn L3: <https://www.w3.org/TR/webauthn-3/>
- Validation source: SimpleWebAuthn `mldsa_support` branch.

---

## 2. Workspace inventory (as found on `feature/ml-dsa`)

Solution targets a **single TFM: `net10.0`** (see `Src/Fido2/Fido2.csproj`).
No multi-targeting / `#if NET10_0_OR_GREATER` guards required.

Files affected by this work:

| Concern | File |
|---|---|
| COSE enums (`Algorithm`, `KeyType`, `KeyTypeParameter`, …) | `Src/Fido2.Models/COSETypes.cs` |
| Credential public-key parsing & verification dispatch | `Src/Fido2/Objects/CredentialPublicKey.cs` |
| Assertion verification entry point | `Src/Fido2/AuthenticatorAssertionResponse.cs` |
| `pubKeyCredParams` defaults & `PubKeyCredParam` constants | `Src/Fido2.Models/CredentialCreateOptions.cs` |
| Registration parameters | `Src/Fido2/RequestNewCredentialParams.cs` |
| Tests | `Tests/Fido2.Tests/` (xUnit; `InternalsVisibleTo("Fido2.Tests")` already configured) |

Key facts about the existing dispatch:

- `CredentialPublicKey.Verify(...)` switches on `_type` (`EC2 / RSA / OKP`).
  There is **no** pre-existing verifier-abstraction interface, so the
  ML-DSA path will be added as a new `case COSE.KeyType.AKP:` rather than
  refactoring to an interface registry.
- `AuthenticatorAssertionResponse.VerifyAsync` already builds
  `data = authenticatorData || SHA256(clientDataJSON)` and calls
  `cpk.Verify(data, Signature)`. ML-DSA needs **no pre-hash** — `MLDsa.VerifyData`
  is the correct API.

`MLDsa` in .NET 10 is decorated experimental — we will use scoped
`#pragma warning disable SYSLIB5006` only inside the new ML-DSA verifier file.

---

## 3. Design summary

- Add `AKP` to `COSE.KeyType` and `ML_DSA_44/65/87` to `COSE.Algorithm`.
- Add a new `case COSE.KeyType.AKP` in `CredentialPublicKey`'s constructor
  switch and `Verify` switch.
- Validate AKP keys before any crypto:
  1. `kty == AKP`
  2. `alg` is present and ∈ {-48, -49, -50}
  3. `pub` (param `-1`) is present and is a CBOR byte string
  4. `pub.Length` matches the ML-DSA parameter set
  5. `signature.Length` matches the ML-DSA parameter set (checked at verify time)
- Encapsulate ML-DSA crypto in `internal static class MLDsaCoseVerifier`
  inside `Src/Fido2/Objects/`. This is the **only** place that touches the
  experimental API — `SYSLIB5006` is suppressed solely in that file.
- Import COSE `pub` bytes directly via `MLDsa.ImportMLDsaPublicKey` (raw
  FIPS 204 bytes). Do **not** convert to JWK/SPKI.
- Keep ML-DSA out of `PubKeyCredParam.Defaults`. Provide an explicit
  helper `WithExperimentalMLDsaFirst()` and exposed constants
  `PubKeyCredParam.ML_DSA_44/65/87`.

---

## 4. PR breakdown

Each PR is independently buildable, testable, and shippable.

### PR 1 — COSE model additions & AKP parser

**Code changes**

- `Src/Fido2.Models/COSETypes.cs`
  - `COSE.Algorithm`: add
    ```csharp
    ML_DSA_44 = -48,
    ML_DSA_65 = -49,
    ML_DSA_87 = -50,
    ```
    with `[EnumMember(Value = "ML-DSA-44")]` etc. if/when the enum acquires
    those attributes (currently it does not — match prevailing style).
  - `COSE.KeyType`: add `AKP = 7`.
  - `COSE.KeyTypeParameter`: add `Pub = -1`, `Priv = -2`
    (note: existing entries already reuse `-1`/`-2` per kty; preserve pattern).
  - Add static helpers:
    ```csharp
    public static int GetMLDsaPublicKeySize(Algorithm alg) => alg switch
    {
        Algorithm.ML_DSA_44 => 1312,
        Algorithm.ML_DSA_65 => 1952,
        Algorithm.ML_DSA_87 => 2592,
        _ => throw new ArgumentOutOfRangeException(nameof(alg))
    };

    public static int GetMLDsaSignatureSize(Algorithm alg) => alg switch
    {
        Algorithm.ML_DSA_44 => 2420,
        Algorithm.ML_DSA_65 => 3309,
        Algorithm.ML_DSA_87 => 4627,
        _ => throw new ArgumentOutOfRangeException(nameof(alg))
    };
    ```

- `Src/Fido2/Objects/CredentialPublicKey.cs`
  - Add field `internal readonly byte[]? _mldsaPublicKey;`
  - In `CredentialPublicKey(CborMap cpk)` add:
    ```csharp
    case COSE.KeyType.AKP:
        _mldsaPublicKey = ValidateAkp(cpk, _alg);
        return;
    ```
  - Add `private static byte[] ValidateAkp(CborMap cpk, COSE.Algorithm alg)`
    enforcing the order in §3.
  - **No `Verify(...)` change in this PR** — AKP keys parse but
    `Verify` will throw the existing "unknown kty" path until PR 2 wires
    the verifier. (Document this explicitly in the PR description.)

**Tests (`Tests/Fido2.Tests/MLDsaCoseTests.cs`, new)**

- COSE constants:
  - `(int)COSE.Algorithm.ML_DSA_44 == -48`, `_65 == -49`, `_87 == -50`.
  - `(int)COSE.KeyType.AKP == 7`.
  - `(int)COSE.KeyTypeParameter.Pub == -1`.
- Size helpers return correct sizes for each alg, throw for others.
- AKP parser happy paths for each of `-48/-49/-50` with correctly sized
  pub byte strings.
- AKP parser failures:
  - Missing `-1` → throws.
  - `-1` not a byte string → throws.
  - Wrong public key length → throws.
  - `kty=AKP` paired with `alg=ES256` → throws.
  - `kty=EC2` paired with `alg=ML_DSA_65` → existing EC2 path throws
    (regression check).

### PR 2 — ML-DSA verifier + dispatch

**Code changes**

- New file `Src/Fido2/Objects/MLDsaCoseVerifier.cs`:
  ```csharp
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
  ```
  Wrap the file's body with `#pragma warning disable SYSLIB5006` /
  `restore SYSLIB5006`. **No other file** suppresses this warning.

- `Src/Fido2/Objects/CredentialPublicKey.cs` — extend `Verify` switch:
  ```csharp
  case COSE.KeyType.AKP:
      return MLDsaCoseVerifier.Verify(_alg, _mldsaPublicKey!, data, signature);
  ```

**Tests (extend `MLDsaCoseTests.cs` or new `MLDsaVerifierTests.cs`)**

- Mapping tests: `Map(-48/-49/-50)` returns the correct `MLDsaAlgorithm`;
  `Map(ES256)` throws `NotSupportedException`.
- Crypto round-trip (gated on `MLDsa.IsSupported`; skip otherwise):
  for each parameter set,
  1. `using var k = MLDsa.GenerateKey(alg);`
  2. Export the raw public key.
  3. Build a CBOR map `{1:7, 3:<alg>, -1:<pub>}` and construct
     `CredentialPublicKey`.
  4. `byte[] data = RandomNumberGenerator.GetBytes(64);`
     `byte[] sig  = k.SignData(data);`
  5. Assert `cpk.Verify(data, sig) == true`.
  6. Flip a byte in `data` → expect `false`.
  7. Flip a byte in `sig` → expect `false`.
  8. Truncate `sig` by one byte → expect `false`
     (signature-length pre-check).
- Platform negative test: when `!MLDsa.IsSupported`, calling
  `MLDsaCoseVerifier.Verify(...)` throws `PlatformNotSupportedException`.
  Use `Skip.If` or a runtime check to keep this conditional.

### PR 3 — RP opt-in advertisement

**Code changes** — `Src/Fido2.Models/CredentialCreateOptions.cs`

- Add to `PubKeyCredParam`:
  ```csharp
  public static readonly PubKeyCredParam ML_DSA_44 = new(COSE.Algorithm.ML_DSA_44);
  public static readonly PubKeyCredParam ML_DSA_65 = new(COSE.Algorithm.ML_DSA_65);
  public static readonly PubKeyCredParam ML_DSA_87 = new(COSE.Algorithm.ML_DSA_87);

  /// <summary>
  /// Experimental: returns a list that prefers ML-DSA-65, with the
  /// existing classical defaults retained as fallback. Browser /
  /// authenticator support for ML-DSA is currently sparse.
  /// </summary>
  public static IReadOnlyList<PubKeyCredParam> WithExperimentalMLDsaFirst() =>
      [ ML_DSA_65, Ed25519, ES256, RS256, PS256, ES384, RS384, PS384, ES512, RS512, PS512 ];
  ```
- **Do not** modify `Defaults` or `RequestNewCredentialParams.PubKeyCredParams`
  default — ML-DSA stays opt-in.

**Tests**

- `PubKeyCredParam.Defaults` contains no `ML_DSA_*` entries.
- `WithExperimentalMLDsaFirst()[0].Alg == COSE.Algorithm.ML_DSA_65`.
- `WithExperimentalMLDsaFirst()` still contains `ES256` and `RS256`.

### PR 4 — Documentation + (optional) end-to-end fixture

**Docs**

- New `Documentation/MLDSA-Support.md`:
  - Experimental notice.
  - Supported COSE alg IDs and parameter sets.
  - Runtime requirement: `MLDsa.IsSupported == true` (.NET 10 + platform
    crypto provider).
  - Opt-in example using `PubKeyCredParam.WithExperimentalMLDsaFirst()`.
  - Note that there is no JWK/SPKI conversion in the WebAuthn path —
    raw COSE `pub` bytes are imported directly.
- Add a row to any algorithm support matrix in the README, marked
  "experimental, opt-in, requires .NET 10".

**Optional E2E assertion test**

- Generate ML-DSA key, build an `AttestedCredentialData` containing the
  AKP COSE key, run a synthetic registration via the public `Fido2` API,
  then synthesise an assertion (sign `authData || SHA256(clientDataJSON)`)
  and validate via `Fido2.MakeAssertionAsync`. If the existing test
  fixtures make this disproportionate, ship only the focused test in PR 2.

---

## 5. Phases that require no code change

- **Assertion ceremony** (`AuthenticatorAssertionResponse.VerifyAsync`)
  already concatenates `authData || SHA256(clientDataJSON)` and calls
  `cpk.Verify`. Once PR 2 lands, AKP routing is automatic.
- **Registration ceremony**: attestation parsing constructs
  `CredentialPublicKey` from the attested credential data. Once PR 1's
  AKP case lands, AKP keys are accepted. No attestation format requires
  AKP-specific handling at this stage.

---

## 6. Validation order (security-critical)

`ValidateAkp` and `MLDsaCoseVerifier.Verify` together must enforce, in
this order, before any crypto provider call:

1. `kty == AKP`
2. `alg` present
3. `alg ∈ {-48, -49, -50}`
4. `pub` present and is a CBOR byte string
5. `pub.Length == GetMLDsaPublicKeySize(alg)`
6. `signature.Length == GetMLDsaSignatureSize(alg)` (at `Verify` time)
7. `MLDsa.IsSupported` — otherwise throw `PlatformNotSupportedException`

Only then call `MLDsa.ImportMLDsaPublicKey` and `VerifyData`.

---

## 7. Security review checklist (gate before merge)

- [ ] No hand-written ML-DSA primitive code anywhere in the repo.
- [ ] `SYSLIB5006` suppressed only in `MLDsaCoseVerifier.cs`.
- [ ] `PubKeyCredParam.Defaults` unchanged.
- [ ] AKP keys are only verified through the AKP branch — no silent
      downgrade to ECDSA/EdDSA/RSA.
- [ ] Validation order in §6 enforced before any provider call.
- [ ] All existing challenge / origin / RP-ID / UV / UP / sign-counter /
      extension checks in `AuthenticatorAssertionResponse` are unchanged.
- [ ] No JWK/SPKI conversion in the WebAuthn assertion path.
- [ ] Tests cover: missing `alg`, invalid `alg`, unsupported AKP algorithm,
      missing `pub`, wrong `pub` length, wrong signature length, tampered
      data, tampered signature.

---

## 8. Definition of done

- `dotnet build` clean (no new warnings outside the scoped
  `SYSLIB5006` suppression).
- `dotnet test` green for the existing suite on `net10.0`.
- New ML-DSA crypto tests pass on a host where
  `MLDsa.IsSupported == true`; they skip cleanly otherwise.
- `kty=AKP` COSE keys with `alg ∈ {-48, -49, -50}` parse, dispatch,
  and verify through `CredentialPublicKey.Verify`.
- Default `pubKeyCredParams` is byte-identical to the pre-change output.
- `PubKeyCredParam.WithExperimentalMLDsaFirst()` returns
  `[-49, …classical fallbacks]`.
- `Documentation/MLDSA-Support.md` published; algorithm matrix updated.

---

## 9. Tracking checklist

PR 1 — COSE model & AKP parser
- [ ] `COSETypes.cs` enum additions
- [ ] Size helpers
- [ ] `CredentialPublicKey` AKP parsing case + `ValidateAkp`
- [ ] `MLDsaCoseTests.cs` (constants + parser)
- [ ] `dotnet test` green

PR 2 — ML-DSA verifier
- [ ] `MLDsaCoseVerifier.cs`
- [ ] `CredentialPublicKey.Verify` AKP case
- [ ] Mapping + crypto round-trip tests (gated on `MLDsa.IsSupported`)
- [ ] `dotnet test` green

PR 3 — Opt-in advertisement
- [ ] `PubKeyCredParam.ML_DSA_*` constants
- [ ] `WithExperimentalMLDsaFirst()`
- [ ] Defaults regression test
- [ ] `dotnet test` green

PR 4 — Docs (+ optional E2E)
- [ ] `Documentation/MLDSA-Support.md`
- [ ] Algorithm matrix entry
- [ ] (optional) End-to-end assertion fixture test
- [ ] `dotnet test` green
