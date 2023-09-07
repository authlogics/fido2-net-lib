using System.Collections.Generic;
using Authlogics.Core.Models.Fido2;

namespace Fido2Demo
{
    public static class Extensions
    {
        public static Fido2NetLib.Objects.PublicKeyCredentialType Translate(this CredentialType value)
        {
            if (value == CredentialType.PublicKey) return Fido2NetLib.Objects.PublicKeyCredentialType.PublicKey;
            return Fido2NetLib.Objects.PublicKeyCredentialType.Invalid;
        }

        public static CredentialType Translate(this Fido2NetLib.Objects.PublicKeyCredentialType value)
        {
            if (value == Fido2NetLib.Objects.PublicKeyCredentialType.PublicKey) return CredentialType.PublicKey;
            return CredentialType.Invalid;
        }

        public static Fido2NetLib.Objects.PublicKeyCredentialDescriptor Translate(this CredentialDescriptor value)
        {
            return new Fido2NetLib.Objects.PublicKeyCredentialDescriptor(value.Type.Translate(), value.Id, value.Transports.Translate());
        }

        public static Fido2NetLib.Objects.AuthenticatorTransport Translate(this AuthenticatorTransport value)
        {
            if (value == AuthenticatorTransport.Usb) return Fido2NetLib.Objects.AuthenticatorTransport.Usb;
            if (value == AuthenticatorTransport.Nfc) return Fido2NetLib.Objects.AuthenticatorTransport.Nfc;
            if (value == AuthenticatorTransport.Ble) return Fido2NetLib.Objects.AuthenticatorTransport.Ble;

            return Fido2NetLib.Objects.AuthenticatorTransport.Internal;
        }

        public static AuthenticatorTransport Translate(this Fido2NetLib.Objects.AuthenticatorTransport value)
        {
            if (value == Fido2NetLib.Objects.AuthenticatorTransport.Usb) return AuthenticatorTransport.Usb;
            if (value == Fido2NetLib.Objects.AuthenticatorTransport.Nfc) return AuthenticatorTransport.Nfc;
            if (value == Fido2NetLib.Objects.AuthenticatorTransport.Ble) return AuthenticatorTransport.Ble;

            return AuthenticatorTransport.Internal;
        }

        public static Fido2NetLib.Objects.AuthenticatorTransport[] Translate(this IEnumerable<AuthenticatorTransport> value)
        {
            var results = new List<Fido2NetLib.Objects.AuthenticatorTransport>();

            if (value != null)
            {
                foreach (var cred in value)
                {
                    results.Add(Translate(cred));
                }
            }

            return results.ToArray();
        }

        public static AuthenticatorTransport[] Translate(this IEnumerable<Fido2NetLib.Objects.AuthenticatorTransport> value)
        {
            var results = new List<AuthenticatorTransport>();

            if (value != null)
            {
                foreach (var cred in value)
                {
                    results.Add(Translate(cred));
                }
            }

            return results.ToArray();
        }
    }
}
