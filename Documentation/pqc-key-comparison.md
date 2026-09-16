# PQC security key comparison: YubiKey "alpha 6" vs "alpha 8"

Date: 2026-09-16
Branch: `feature/ml-dsa`
Environment: Windows 11 Pro 10.0.26200, .NET 10.0.10 (`MLDsa.IsSupported == true`), Chrome, Demo server at `https://localhost:5001`

## Summary

Two pre-release Yubico PQC test keys were exercised against the Demo relying party.
Alpha 6 registers and authenticates ML-DSA credentials end to end. Alpha 8 fails
registration of any ML-DSA credential when the browser goes through the Windows
WebAuthn platform API (`webauthn.dll`), showing "Unknown device state" in the Windows
security-key dialog.

Root cause: alpha 8 attests every PQC credential with a fixed **ML-DSA-87 attestation
certificate (7618 bytes) and ML-DSA-87 attestation signature (4627 bytes)**. The resulting
`makeCredential` response is 13.7 to 15 KB, above the **7609-byte CTAPHID maximum message
size** (one init packet plus 128 continuation packets). Windows rejects the response at the
HID layer; the key keeps streaming continuation packets, which the Windows UI reports as
"Unknown device state". Chrome's own CTAP stack (usable only in an elevated Chrome with the
native Windows API disabled) reassembles the oversized message, so registration works
there. Once a credential exists, **authentication works through Windows too**, because an
assertion response is only about 4.8 KB.

Nothing in `fido2-net-lib` is involved in the Windows failure: the request never reaches
the relying party. The library verifies every ceremony that does arrive, with one gap: it
cannot yet build an attestation public key from an ML-DSA certificate (see
[Implications for fido2-net-lib](#implications-for-fido2-net-lib)).

## The keys

Both keys enumerate as `Yubico YubiKey OTP+FIDO+CCID` (USB VID 1050, PID 0407) with a PIN set.
Decoded `authenticatorGetInfo` (captured from the Windows WebAuthN event log):

| Field | Alpha 6 | Alpha 8 |
|---|---|---|
| AAGUID | `f8a011f3-8c0a-4d15-8006-17111f9edc7d` | `2165deef-e5a8-4efa-9fe7-fea9ddb2d227` |
| versions | U2F_V2, FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1, FIDO_2_3 | same |
| algorithms | -7, -8, -35, -48, -49, -50 | same |
| attestationFormats | `["packed"]` | same |
| maxMsgSize | 4928 | same |
| pinUvAuthProtocols | [2, 1] | same |
| transports | nfc, usb | nfc, usb, **smart-card** |
| minPINLength | 4 | 6 |
| options | ep, rk, up, credMgmt, clientPin, largeBlobs, pinUvAuthToken, makeCredUvNotRqd, ... | same |

Everything the keys advertise is identical apart from the AAGUID, the extra `smart-card`
transport and the minimum PIN length. The difference is in how they attest.

## Relying-party options used

Unless stated otherwise every registration used the Demo defaults:
`pubKeyCredParams = [-50, -49, -48, -7, -257, -8]` (ML-DSA-87 first), `attestation = none`,
`authenticatorAttachment = cross-platform`, `residentKey = preferred`,
`userVerification = preferred`, timeout 60 s.

## Ceremony results

| # | Key | Path | Options | Result |
|---|---|---|---|---|
| 1 | alpha 6 | Chrome → Windows webauthn.dll | defaults | Registered ML-DSA-87. Device response 3536 B (`packed`, ES256 x5c attestation); Windows rewrote it to `none`. Library verified. |
| 2 | alpha 6 | Chrome → Windows | sign in | 4627 B ML-DSA-87 signature verified. |
| 3 | alpha 8 | Chrome → Windows | defaults | **Failed in Windows**: HID `ERROR_BAD_LENGTH` reading the makeCredential response, then stray continuation packets, UI "Unknown device state". Request never reached the server. |
| 4 | alpha 8 | Chrome → Windows | ML-DSA-44 only | Same failure. |
| 5 | alpha 8 | Chrome → Windows | ES256 only, attestation direct | Registered. 881 B response, `packed`, ES256 x5c cert (563 B, "Yubico FIDO EE Serial 190523844"). Library verified. |
| 6 | alpha 8 | elevated Chrome (own CTAP stack) | defaults | Registered ML-DSA-87. Chrome received `{packed, authData 2706 B, attStmt}` and stripped the attestation. Library verified. |
| 7 | alpha 8 | elevated Chrome | defaults, attestation direct | CTAP succeeded, response **15005 B**: attStmt alg -50, sig 4627 B, x5c ML-DSA-87 cert 7618 B. Library failed: `Unknown oid. Was 2.16.840.1.101.3.4.3.19`. |
| 8 | alpha 8 | elevated Chrome | ML-DSA-44 only, attestation direct | CTAP succeeded, response **13725 B**: credential ML-DSA-44 (1312 B key) but the **same** ML-DSA-87 attestation sig and cert. Same library error. |
| 9 | alpha 8 | elevated Chrome | sign in (credential from #6) | 4627 B signature verified. |
| 10 | alpha 8 | **normal Chrome → Windows** | sign in (credential from #6) | Windows completed GetAssertion; 4627 B signature verified by the library. |

The 1280-byte difference between #7 and #8 is exactly the difference between the two
credential public key sizes (2592 vs 1312). The attestation part is identical, so alpha 8
uses one attestation key for all PQC credentials. That certificate alone exceeds the whole
CTAPHID budget, so no PQC credential from alpha 8 can be registered over USB HID through
Windows, whatever parameter set the relying party requests.

## What the Windows failure looks like

From `Microsoft-Windows-WebAuthN/Operational` for an alpha 8 ML-DSA registration
(identical for ML-DSA-87 and ML-DSA-44):

1. `INIT`, `getInfo`, `getPinRetries` → Windows prompts for the PIN (same as alpha 6).
2. `INIT`, `getInfo`, `getKeyAgreement`, `getPinToken` (PIN accepted), `makeCredential`,
   keepalives until the touch.
3. About 300 ms after the touch: CTAPHID receive fails with `0x18 ERROR_BAD_LENGTH`
   ("the command length is incorrect"), device thread ends with `0x80090320`.
4. Windows retries `INIT` and receives **continuation packets** (sequence numbers 4 to 0x0E)
   instead of an INIT reply: the key is still streaming the remainder of the rejected
   response and the 7-bit sequence counter has wrapped. Windows logs
   `0x8007000D The data is invalid`, device state `0x9`, and the UI shows
   "Unknown device state".
5. Once the stream drains Windows re-INITs, probes again, asks for the PIN again, and the
   cycle repeats until the user cancels (`0x800704C7`).

## Things that are not the cause

- **`attestation: "none"` does not avoid it.** The WebAuthn attestation preference is
  applied by the client after the response has crossed the transport. CTAP2 has no way to
  ask the authenticator to omit attestation; alpha 8 advertises only `packed`, and neither
  Windows nor Chrome send CTAP 2.2's `attestationFormatsPreference`. Alpha 6's ceremony #1
  shows the same thing: the device returned a 3536-byte packed response and Windows
  rewrote it to `none`.
- **The credProtect extension is not involved.** Windows adds `credProtect: 2` to its
  requests; alpha 8's ES256 registration through Windows carried it and worked (881 B).
  The 15 KB response in ceremony #7 contained no credProtect output at all.
- **The credential parameter set is not the trigger.** ML-DSA-44 fails exactly like
  ML-DSA-87 (ceremonies #4 and #8).

## Implications for fido2-net-lib

- ML-DSA credentials (COSE `kty = 7` AKP, algs -48/-49/-50) are parsed and verified for
  both registration (self-attestation or attestation `none`) and assertion. All successful
  ceremonies above were verified by the library on Windows CNG ML-DSA.
- **Gap:** `COSE.GetKeyTypeFromOid` (`Src/Fido2.Models/COSETypes.cs`) and the
  `CredentialPublicKey(X509Certificate2, alg)` constructor (`Src/Fido2/Objects/CredentialPublicKey.cs`)
  have no ML-DSA branch, so a packed attestation whose x5c leaf holds an ML-DSA key fails with
  `Unknown oid. Was 2.16.840.1.101.3.4.3.19` (id-ml-dsa-87; -44 is `.17`, -65 is `.18`).
  The fix is to map those OIDs to `KeyType.AKP`, export the raw key with
  `X509Certificate2.GetMLDsaPublicKey()` (.NET 10), check the certificate's parameter set
  against the attestation `alg`, and let the existing AKP `Verify` path handle the
  signature. The rest of the packed checks (v3, subject C/O/OU/CN, AAGUID extension,
  CA=false) already pass on alpha 8's certificate.
- The alpha 8 attestation certificate is issued by "Yubico 2026-07 FIDO Preview CA". The
  AAGUID is not in the FIDO Metadata Service, so `TrustAnchor.Verify` skips chain validation
  and the attestation type is reported as AttCa without root verification. Validating a
  chain of ML-DSA certificates would additionally depend on OS support in `X509Chain`.

## Reproducing

1. Run the Demo (`dotnet run --project Demo/Demo.csproj`) and open `https://localhost:5001`.
   The Advanced settings include an **Algorithms** dropdown that overrides the advertised
   `pubKeyCredParams`. The controller logs each raw payload and a parsed summary under the
   `PQC-DIAG` prefix, before verification, so rejected responses are captured too.
2. To see the CTAP traffic when a request never reaches the server:

   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-WebAuthN/Operational" |
     Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-10) } |
     Sort-Object TimeCreated | Format-List TimeCreated, Id, Message
   ```

   Event 2225 carries request/response hex (`getInfo` CBOR, `makeCredential` responses),
   2226 carries HID errors, 2110 the device state shown by the UI.
3. To bypass `webauthn.dll` and use Chrome's own CTAP stack (requires elevation, because
   Windows blocks raw FIDO HID access for non-admin processes; use a separate profile so it
   does not hand off to a running Chrome):

   ```powershell
   Start-Process "C:\Program Files\Google\Chrome\Application\chrome.exe" -Verb RunAs -ArgumentList `
     '--disable-features=WebAuthenticationUseNativeWinApi', `
     '--user-data-dir=C:\Temp\chrome-fido', `
     '--enable-logging', '--v=1', '--log-file=C:\Temp\chrome-fido.log', `
     'https://localhost:5001/'
   ```

   Chrome's FIDO log lines (`FIDO: DEBUG: ctap2_device_operation.h`) show the CBOR requests
   and responses; `chrome://device-log` shows the same in the browser. The dev certificate
   is not trusted in the throwaway profile, but `localhost` remains a secure context.
4. WebAuthn calls are rejected immediately with `NotAllowedError` if the tab is hidden or the
   window is behind another; keep the browser window in the foreground during ceremonies.

## Appendix: alpha 8 PQC attestation certificate

```
Subject:   CN=Yubico FIDO EE Serial 321575808, OU=Authenticator Attestation, O=Yubico AB, C=SE
Issuer:    CN=Yubico 2026-07 FIDO Preview CA
Validity:  2026-07-10 to 2027-12-31
Key:       id-ml-dsa-87 (2.16.840.1.101.3.4.3.19), 2592-byte public key
Signature: id-ml-dsa-87 (2.16.840.1.101.3.4.3.19)
Size:      7618 bytes DER
Extensions: id-fido-gen-ce-aaguid = 2165deef-e5a8-4efa-9fe7-fea9ddb2d227, transports, BasicConstraints CA=false
```
