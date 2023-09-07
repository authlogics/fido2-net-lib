using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Authlogics.Core.Models.Fido2;
using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using static Fido2NetLib.Fido2;


namespace Fido2Demo;

[Route("api/[controller]")]
public class MyController : Controller
{
    private IFido2 _fido2;
    public static IMetadataService _mds;
    //public static readonly DevelopmentInMemoryStore DemoStorage = new DevelopmentInMemoryStore();
    public static readonly FidoManager FidoManager = new FidoManager();

    public MyController(IFido2 fido2)
    {
        _fido2 = fido2;
    }

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username, 
                                            [FromForm] string displayName,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification)
    {
        try
        {
            if (string.IsNullOrEmpty(username)) throw new ArgumentException($"Argument {nameof(username)} may not be null or empty", nameof(username));

            // 1. Get user from DB by username
            var result = FidoManager.GetUserAndKeys(username);
            var user = result.User;

            if (user == null) throw new ApplicationException("User not found.");

            // 2. Get user existing keys by username
            //var existingKeys = FidoManager.GetCredentialsByUser(username).Select(c => c.Descriptor).ToList();
            var existingKeys = result.ExistingKeys;

            // 3. Create options
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType)) authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs() { Attestation = attType },
                CredProps = true
            };

            var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);

            // 4. Temporarily store options, session/in-memory cache/redis/db
            //We'll use this technique for now as we dont have the username in makecredential
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());
            //FidoManager.SaveUserOptions(user, options.ToJson(), "");

            // 5. return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new CredentialCreateOptions { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. get the options we sent the client
            //var userOptions = FidoManager.GetUserOptions(new Fido2User() { Name = username });
            //var jsonOptions = userOptions.AttestationOptions;

            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
            {
                //TODO (JW): we would have to create an AD table just to store credential unqiue ids to support this 
                //Due to the way we store credentials by user, this isnt easy or efficient otherwise
                await Task.Delay(0, cancellationToken);

                return true;
            };

            // 2. Verify and make the credentials
            var success = await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken);

            // 3. Store the credentials in db
            FidoManager.AddCredentialToUser(options.User, new FidoCredential
            {
                Type = success.Result.Type.Translate(),
                Id = success.Result.Id,
                Descriptor = new CredentialDescriptor(success.Result.Id),
                PublicKey = success.Result.PublicKey,
                UserHandle = success.Result.User.Id,
                SignCount = (int) success.Result.Counter,
                CredType = success.Result.CredType,
                RegDate = DateTime.Now,
                AaGuid = success.Result.AaGuid,
                Transports = success.Result.Transports.Translate(),
                BE = success.Result.BE,
                BS = success.Result.BS,
                AttestationObject = success.Result.AttestationObject,
                AttestationClientDataJson = success.Result.AttestationClientDataJSON,
                DevicePublicKeys = new List<byte[]>() { success.Result.DevicePublicKey }
            });

            // 4. return "ok" to the client
            return Json(success);
        }
        catch (Exception e)
        {
            return Json(new CredentialMakeResult(status: "error", errorMessage: FormatException(e), result: null));
        }
    }

    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost([FromForm] string username, [FromForm] string userVerification)
    {
        try
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();

            var result = FidoManager.GetUserAndKeys(username);
            var user = result.User;

            existingCredentials = result.ExistingKeys;
            
            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()
            };

            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                exts
            );

            // 4. Temporarily store options, session/in-memory cache/redis/db
            //Normally we will need to request the username again or keep it in a form variable
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());
            HttpContext.Session.SetString("fido2.assertionUser", username);
            //FidoManager.SaveUserOptions(user, "", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }

        catch (Exception e)
        {
            return Json(new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) });
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
            var username = HttpContext.Session.GetString("fido2.assertionUser");
            var options = AssertionOptions.FromJson(jsonOptions);

            var user = FidoManager.GetUser(username);

            // 2. Get registered credential from database
            var credential = FidoManager.GetCredentialById(user, clientResponse.Id) ?? throw new Exception("Unknown credentials");

            // 3. Get credential counter from database
            var storedCounter = credential.SignCount;

            // 4. Create callback to check if userhandle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                //As per attestation we cant / may not have to do this
                await Task.Delay(0, cancellationToken);
                return true;
            };

            // 5. Make the assertion
            var res = await _fido2.MakeAssertionAsync(clientResponse, options, credential.PublicKey, credential.DevicePublicKeys, (uint)storedCounter, callback, cancellationToken: cancellationToken);
            if (res.DevicePublicKey is not null) credential.DevicePublicKeys.Add(res.DevicePublicKey);

            // 6. Store the updated counter and trigger save on the credential
            FidoManager.UpdateCounter(user, res.CredentialId, res.Counter);

            // 7. return OK to client
            return Json(res);
        }
        catch (Exception e)
        {
            return Json(new AssertionVerificationResult { Status = "error", ErrorMessage = FormatException(e) });
        }
    }
}
