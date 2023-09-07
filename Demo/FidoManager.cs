using Fido2NetLib.Development;
using Fido2NetLib;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System;
using System.Linq;
using Authlogics.Core;
using System.Text;
using Authlogics.Core.Models.Fido2;
using Fido2NetLib.Objects;
using Microsoft.CodeAnalysis.CSharp.Syntax;

#nullable enable

namespace Fido2Demo
{
    public class FidoManager
    {
        public Fido2User? GetUser(string username)
        {
            var user = new User(username);
            user.LoadProtected();

            if (!user.Exists) return null;

            var fidoUser = new Fido2User()
            {
                Name = username,
                Id = Encoding.UTF8.GetBytes(user.AccountName),
                DisplayName = user.AccountName
            };

            return fidoUser;
        }

        public (Fido2User? User, List<PublicKeyCredentialDescriptor> ExistingKeys) GetUserAndKeys(string username)
        {
            var existingKeys = new List<PublicKeyCredentialDescriptor>();
            var user = new User(username);
            user.LoadProtected();

            if (!user.Exists) return (null, existingKeys);

            var fidoUser = new Fido2User()
            {
                Name = username,
                Id = Encoding.UTF8.GetBytes(user.AccountName),
                DisplayName = user.AccountName
            };

            var credentials = user.Credentials.OfType<FidoCredential>().ToList();

            foreach ( var cred in credentials )
            {
                var desc = cred.Descriptor;
                var existingKey = new PublicKeyCredentialDescriptor(desc.Type.Translate(), desc.Id, desc.Transports.Translate());

                existingKeys.Add(existingKey);
            }
            return (fidoUser, existingKeys);
        }

        public void SaveUserOptions(Fido2User fidoUser, string attestationOptions, string assertionOptions)
        {
            var user = new User(fidoUser.Name);
            user.LoadProtected();

            user.CredentialOptions = new CredentialOptions()
            {
                AttestationOptions = attestationOptions,
                AssertionOptions = assertionOptions
            };

            user.Save();
        }

        public (string AttestationOptions, string AssertionOptions) GetUserOptions(Fido2User fidoUser, string attestationOptions, string assertionOptions)
        {
            var user = new User(fidoUser.Name);
            user.LoadProtected();

            return (user.CredentialOptions.AttestationOptions, user.CredentialOptions.AssertionOptions);
        }

        public List<FidoCredential> GetCredentialsByUser(Fido2User fidoUser)
        {
            var user = new User(fidoUser.Name);
            user.LoadProtected();

            return user.Credentials.OfType<FidoCredential>().ToList();
        }

        public FidoCredential? GetCredentialById(Fido2User fidoUser, byte[] credentialId)
        {
            var credentials = GetCredentialsByUser(fidoUser);

            return credentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
        }

        public void UpdateCounter(Fido2User fidoUser, byte[] credentialId, uint counter)
        {
            var cred = GetCredentialById(fidoUser, credentialId);
            if (cred == null) throw new ApplicationException("Credential not found");

            cred.SignCount = (int) counter;

            var user = new User(fidoUser.Name);
            user.LoadProtected();

            user.UpdateCredential(cred);
            user.Save();
        }

        public void AddCredentialToUser(Fido2User fidoUser, FidoCredential credential)
        {
            var user = new User(fidoUser.Name);
            user.LoadProtected();

            credential.UserId = Encoding.UTF8.GetBytes(user.AccountName);
            user.AddCredential(credential);

            user.Save();
        }


    }
}
