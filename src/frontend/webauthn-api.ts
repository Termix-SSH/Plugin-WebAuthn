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

/** app.auth from Termix 26.11.2: the shell runs the browser prompt. */
export interface KeySteps {
  webauthn: (
    ceremonyId: string,
    extra?: Record<string, string | number | boolean>,
  ) => Promise<Record<string, unknown>>;
}

let steps: KeySteps | null = null;

export function setKeySteps(next: KeySteps | null): void {
  steps = next;
}

/** The person closed the browser prompt; nothing to report. */
export class PromptClosed extends Error {
  readonly name = "AbortError";
}

async function runStep(
  ceremonyId: string,
  extra: Record<string, string | number | boolean> = {},
): Promise<void> {
  if (!steps) throw new Error("This Termix version can't run key steps");
  const result = await steps.webauthn(ceremonyId, extra);
  if (result.closed === true) throw new PromptClosed();
  if (result.ok !== true) {
    throw new Error(
      typeof result.error === "string" ? result.error : "The key step failed",
    );
  }
}

export function createWebAuthnApi(api: PluginApiClient) {
  return {
    async list(): Promise<WebAuthnCredentialSummary[]> {
      const { data } = await api.get<{
        credentials?: WebAuthnCredentialSummary[];
      }>("credentials");
      return data.credentials ?? [];
    },

    register(
      name: string,
      userVerification: WebAuthnUserVerification,
    ): Promise<void> {
      return runStep("register", { name, userVerification });
    },

    async remove(id: string): Promise<void> {
      // While the security key step is on, removing a key needs a tap.
      if ((await this.factorStatus()).enabled) {
        await runStep("remove-key", { credentialId: id });
        return;
      }
      await api.delete(`credentials/${encodeURIComponent(id)}`);
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
      await runStep("disable-factor");
    },
  };
}
