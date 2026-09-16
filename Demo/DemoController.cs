using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Fido2Demo;

[Route("api/[controller]")]
public class DemoController : Controller
{
    private readonly IFido2 _fido2;
    private readonly ILogger<DemoController> _logger;
    public static IMetadataService _mds;
    public static readonly DevelopmentInMemoryStore DemoStorage = new();

    public DemoController(IFido2 fido2, ILogger<DemoController> logger)
    {
        _fido2 = fido2;
        _logger = logger;
    }

    // Advertise all supported COSE algorithms to the client during registration,
    // with the new post-quantum ML-DSA algorithms (COSE -48, -49, -50) listed
    // ahead of classical RSA/ECC so authenticators that support them are
    // preferred. Within the ML-DSA family the strongest parameter set is listed
    // first (ML-DSA-87, then -65, then -44) so an authenticator that supports
    // more than one will pick the strongest. See Documentation/MLDSA-Support.md.
    private static readonly IReadOnlyList<PubKeyCredParam> _pubKeyCredParams =
    [
        // Post-quantum (ML-DSA) — strongest first
        PubKeyCredParam.ML_DSA_87,
        PubKeyCredParam.ML_DSA_65,
        PubKeyCredParam.ML_DSA_44,
        // Classical fallbacks — limited to algorithms supported by real authenticators
        PubKeyCredParam.ES256,     // Required by CTAP2; supported by virtually all authenticators
        PubKeyCredParam.RS256,     // Windows Hello, platform authenticators
        PubKeyCredParam.Ed25519,   // Newer YubiKeys (5+), some recent authenticators
    ];

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    // Parses a comma-separated list of COSE algorithm identifiers (e.g. "-50,-48,-7") into
    // pubKeyCredParams in the given order. Falls back to the demo default list when empty.
    private static IReadOnlyList<PubKeyCredParam> ParsePubKeyCredParams(string algs)
    {
        if (string.IsNullOrWhiteSpace(algs))
            return _pubKeyCredParams;

        var result = new List<PubKeyCredParam>();
        foreach (var token in algs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!int.TryParse(token, out var id) || !Enum.IsDefined(typeof(COSE.Algorithm), id))
                throw new ArgumentException($"Unsupported COSE algorithm identifier '{token}'");

            result.Add(new PubKeyCredParam((COSE.Algorithm)id));
        }

        return result;
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username,
                                            [FromForm] string displayName,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification,
                                            [FromForm] string algs = null)
    {
        try
        {

            if (string.IsNullOrEmpty(username))
            {
                username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
            }

            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Create options
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                CredProps = true
            };

            // Optional override of the advertised algorithms (in preference order), selected in the demo UI.
            var pubKeyCredParams = ParsePubKeyCredParams(algs);

            var options = _fido2.RequestNewCredential(new RequestNewCredentialParams { User = user, ExcludeCredentials = existingKeys, AuthenticatorSelection = authenticatorSelection, AttestationPreference = attType.ToEnum<AttestationConveyancePreference>(), Extensions = exts, PubKeyCredParams = pubKeyCredParams });

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            _logger.LogInformation("PQC-DIAG makeCredentialOptions sent to client: {Json}", options.ToJson());

            // 5. return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error creating credential options for user {Username}", username);
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            LogAttestationDiagnostics(attestationResponse);

            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            if (jsonOptions is null)
                _logger.LogWarning("PQC-DIAG makeCredential: no attestation options found in session (session expired or cookie missing)");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
            {
                var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                if (users.Count > 0)
                    return false;

                return true;
            };

            // 2. Verify and make the credentials
            var credential = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = callback
            }, cancellationToken: cancellationToken);

            _logger.LogInformation("PQC-DIAG trust anchor: metadataAaguid='{Aaguid}' basicFull={BasicFull} privacyCa={PrivacyCa} roots={Roots} trustPathLength={TrustPath} status='{Status}'",
                TrustAnchor.LastMetadataAaGuid, TrustAnchor.LastIsAttestationBasicFull, TrustAnchor.LastIsAttestationPrivacyCA,
                TrustAnchor.LastAttestationRootCertificates?.Length ?? 0, TrustAnchor.LastTrustPath?.Length ?? 0, TrustAnchor.LastValidationStatus);

            // 3. Store the credentials in db
            DemoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                Id = credential.Id,
                PublicKey = credential.PublicKey,
                UserHandle = credential.User.Id,
                SignCount = credential.SignCount,
                AttestationFormat = credential.AttestationFormat,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = credential.AaGuid,
                Transports = credential.Transports,
                IsBackupEligible = credential.IsBackupEligible,
                IsBackedUp = credential.IsBackedUp,
                AttestationObject = credential.AttestationObject,
                AttestationClientDataJson = credential.AttestationClientDataJson
            });

            // 4. return "ok" to the client
            return Json(credential);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error making new credential");
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost([FromForm] string username, [FromForm] string userVerification)
    {
        try
        {
            List<PublicKeyCredentialDescriptor> existingCredentials = [];

            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true
            };

            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams()
            {
                AllowedCredentials = existingCredentials,
                UserVerification = uv,
                Extensions = exts
            });

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }

        catch (Exception e)
        {
            _logger.LogError(e, "Error creating assertion options for user {Username}", username);
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeAssertion")]
    public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the assertion options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = AssertionOptions.FromJson(jsonOptions);

            // 2. Get registered credential from database
            var creds = DemoStorage.GetCredentialById(clientResponse.RawId);
            LogAssertionDiagnostics(clientResponse, creds);
            if (creds is null)
                throw new Exception("Unknown credentials");

            // 3. Get credential counter from database
            var storedCounter = creds.SignCount;

            // 4. Create callback to check if the user handle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            var res = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = clientResponse,
                OriginalOptions = options,
                StoredPublicKey = creds.PublicKey,
                StoredSignatureCounter = storedCounter,
                IsUserHandleOwnerOfCredentialIdCallback = callback
            }, cancellationToken: cancellationToken);

            // 6. Store the updated counter
            DemoStorage.UpdateCounter(res.CredentialId, res.SignCount);

            // 7. return OK to client
            return Json(res);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error making assertion");
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    // ---- PQC diagnostics ---------------------------------------------------
    // These helpers dump the raw WebAuthn payloads plus a parsed summary to the
    // log so that responses from different authenticators (e.g. different PQC
    // firmware builds) can be compared offline. They never throw.

    private void LogAttestationDiagnostics(AuthenticatorAttestationRawResponse raw)
    {
        try
        {
            _logger.LogInformation("PQC-DIAG makeCredential raw response: {Json}", JsonSerializer.Serialize(raw));

            var parsed = AuthenticatorAttestationResponse.Parse(raw);
            var attObj = parsed.AttestationObject;
            var authData = attObj.AuthData;
            var acd = authData.AttestedCredentialData;

            var sb = new StringBuilder("PQC-DIAG attestation summary:");
            sb.Append(" fmt=").Append(attObj.Fmt);
            sb.Append(" attestationObjectBytes=").Append(raw.Response.AttestationObject.Length);
            sb.Append(" attStmtKeys=[").Append(string.Join(",", attObj.AttStmt.Keys.Select(k => k is CborTextString t ? t.Value : k.GetType().Name))).Append(']');

            if (attObj.AttStmt["alg"] is { } algObj)
                sb.Append(" attStmt.alg=").Append(DescribeCbor(algObj));
            if (attObj.AttStmt["sig"] is CborByteString sig)
                sb.Append(" attStmt.sigBytes=").Append(sig.Length);
            if (attObj.AttStmt["x5c"] is CborArray x5c)
            {
                sb.Append(" attStmt.x5cCount=").Append(x5c.Length);
                int i = 0;
                foreach (var certObj in x5c)
                {
                    if (certObj is CborByteString certBytes)
                    {
                        try
                        {
                            var cert = X509CertificateLoader.LoadCertificate(certBytes.Value);
                            sb.Append($" x5c[{i}]={{subject='{cert.Subject}' keyAlgOid={cert.GetKeyAlgorithm()} sigAlgOid={cert.SignatureAlgorithm.Value} bytes={certBytes.Length}}}");
                        }
                        catch (Exception ex)
                        {
                            sb.Append($" x5c[{i}]={{LOAD FAILED {ex.GetType().Name}: {ex.Message}}}");
                        }
                    }
                    i++;
                }
            }

            sb.Append(" flags{UP=").Append(authData.UserPresent)
              .Append(",UV=").Append(authData.UserVerified)
              .Append(",AT=").Append(authData.HasAttestedCredentialData)
              .Append(",ED=").Append(authData.HasExtensionsData)
              .Append(",BE=").Append(authData.IsBackupEligible)
              .Append(",BS=").Append(authData.IsBackedUp).Append('}');
            sb.Append(" signCount=").Append(authData.SignCount);

            if (acd is not null)
            {
                sb.Append(" aaguid=").Append(acd.AaGuid);
                sb.Append(" credentialIdBytes=").Append(acd.CredentialId.Length);
                var cpk = acd.CredentialPublicKey;
                sb.Append(" cpk.alg=").Append((int)cpk.Alg).Append('(').Append(cpk.Alg).Append(')');
                foreach (var (k, v) in cpk.GetCborObject())
                    sb.Append(" cpk[").Append(DescribeCbor(k)).Append("]=").Append(DescribeCbor(v));
                sb.Append(" cpk.cborB64=").Append(Convert.ToBase64String(cpk.GetBytes()));
            }
            else
            {
                sb.Append(" attestedCredentialData=NONE");
            }

            _logger.LogInformation("{Summary}", sb.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PQC-DIAG could not parse attestation response for diagnostics");
        }
    }

    // Renders a CBOR item compactly without depending on the library's internal CBOR types.
    private static string DescribeCbor(CborObject o) => o switch
    {
        CborByteString b => $"bstr[{b.Length}]",
        CborTextString t => $"'{t.Value}'",
        CborArray a => $"array[{a.Length}]",
        CborMap m => $"map[{m.Count}]",
        _ when o.GetType().Name == "CborInteger" => ((long)o).ToString(),
        _ => o.GetType().Name
    };

    private void LogAssertionDiagnostics(AuthenticatorAssertionRawResponse raw, StoredCredential creds)
    {
        try
        {
            _logger.LogInformation("PQC-DIAG makeAssertion raw response: {Json}", JsonSerializer.Serialize(raw));

            var sb = new StringBuilder("PQC-DIAG assertion summary:");
            sb.Append(" authenticatorDataBytes=").Append(raw.Response.AuthenticatorData.Length);
            sb.Append(" signatureBytes=").Append(raw.Response.Signature.Length);
            sb.Append(" userHandleBytes=").Append(raw.Response.UserHandle?.Length ?? 0);

            if (creds is not null)
            {
                var cpk = new CredentialPublicKey(creds.PublicKey);
                sb.Append(" stored.alg=").Append((int)cpk.Alg).Append('(').Append(cpk.Alg).Append(')');
                if (cpk.Alg is COSE.Algorithm.ML_DSA_44 or COSE.Algorithm.ML_DSA_65 or COSE.Algorithm.ML_DSA_87)
                    sb.Append(" expectedMlDsaSignatureBytes=").Append(COSE.GetMLDsaSignatureSize(cpk.Alg));
                sb.Append(" stored.fmt=").Append(creds.AttestationFormat);
                sb.Append(" stored.signCount=").Append(creds.SignCount);
            }
            else
            {
                sb.Append(" storedCredential=NOT FOUND");
            }

            _logger.LogInformation("{Summary}", sb.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PQC-DIAG could not build assertion diagnostics");
        }
    }
}
