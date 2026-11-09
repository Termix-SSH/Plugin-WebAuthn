import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type { PluginApiClient } from "@termix-ssh/plugin-sdk/frontend";

export type WebAuthnUserVerification = "discouraged" | "preferred" | "required";

export type WebAuthnCredentialSummary = {
  id: string;
  name: string;
  deviceType?: string | null;
  backedUp: boolean;
  transports: string[];
  userVerification: WebAuthnUserVerification;
  createdAt: string;
  lastUsedAt?: string | null;
};

type OptionsResponse<T> = { options: T; challengeId: string };

export function isPasskeySupported(): boolean {
  try {
    return browserSupportsWebAuthn();
  } catch {
    return false;
  }
}

export function createWebAuthnApi(api: PluginApiClient) {
  return {
    /** Whether the admin left passkey sign in on. */
    async loginOptions(): Promise<{
      passwordless: boolean;
      onSsoPage: boolean;
    }> {
      try {
        const { data } = await api.get<{
          passwordless?: boolean;
          onSsoPage?: boolean;
        }>("login-options");
        return {
          passwordless: data.passwordless !== false,
          onSsoPage: data.onSsoPage !== false,
        };
      } catch {
        // An older server without the route always allows it.
        return { passwordless: true, onSsoPage: true };
      }
    },
    /**
     * Runs the browser ceremony and returns the body for the login method's
     * verify step. Without a username, discoverable passkeys still work.
     */
    async passkeyAssertion(username?: string) {
      const { data } = await api.post<
        OptionsResponse<PublicKeyCredentialRequestOptionsJSON>
      >("authenticate/options", username ? { username } : {});
      const response = await startAuthentication({
        optionsJSON: data.options,
      });
      return {
        challengeId: data.challengeId,
        response: response as AuthenticationResponseJSON,
      };
    },

    async list(): Promise<WebAuthnCredentialSummary[]> {
      const { data } = await api.get<{
        credentials?: WebAuthnCredentialSummary[];
      }>("credentials");
      return data.credentials ?? [];
    },

    async register(
      name: string,
      userVerification: WebAuthnUserVerification,
    ): Promise<void> {
      const { data } = await api.post<
        OptionsResponse<PublicKeyCredentialCreationOptionsJSON>
      >("register/options", { userVerification });
      const response = await startRegistration({ optionsJSON: data.options });
      await api.post("register/verify", {
        challengeId: data.challengeId,
        name,
        response: response as RegistrationResponseJSON,
      });
    },

    /** A key tap, only while the security key step is on. */
    async factorProof(): Promise<{ response?: AuthenticationResponseJSON }> {
      const { data } = await api.post<{
        options: PublicKeyCredentialRequestOptionsJSON | null;
      }>("second-factor/proof-options");
      if (!data.options) return {};
      const response = await startAuthentication({ optionsJSON: data.options });
      return { response: response as AuthenticationResponseJSON };
    },

    async remove(id: string): Promise<void> {
      const proof = await this.factorProof();
      await api.delete(`credentials/${encodeURIComponent(id)}`, {
        data: proof,
      });
    },

    async factorStatus(): Promise<{ enabled: boolean; keys: number }> {
      const { data } = await api.get<{ enabled: boolean; keys: number }>(
        "second-factor",
      );
      return data;
    },

    async setFactor(enabled: boolean): Promise<void> {
      if (enabled) {
        await api.post("second-factor/enable");
        return;
      }
      await api.post("second-factor/disable", await this.factorProof());
    },
  };
}

/** Runs the browser ceremony for the security key step after a password. */
export async function securityKeyAssertion(options: unknown) {
  const response = await startAuthentication({
    optionsJSON: options as PublicKeyCredentialRequestOptionsJSON,
  });
  return { response: response as AuthenticationResponseJSON };
}
