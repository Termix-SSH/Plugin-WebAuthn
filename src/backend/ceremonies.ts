import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import type { FactorState } from "./factor.js";
import { normalizeUserVerification, type PasskeyService } from "./passkeys.js";
import type { CredentialRepository } from "./repository.js";
import { findUser } from "./users.js";

/** ctx.auth.registerWebAuthnCeremony, Termix 26.11.2 and plugin API 2.8. */
interface Ceremony {
  id: string;
  type: "create" | "get";
  options: (input: {
    userId: string;
    origin: string;
    extra: Record<string, unknown>;
  }) => Promise<{
    publicKey: Record<string, unknown>;
    context?: Record<string, unknown>;
  }>;
  finish: (input: {
    userId: string;
    origin: string;
    extra: Record<string, unknown>;
    context: Record<string, unknown>;
    response: Record<string, unknown>;
  }) => Promise<Record<string, unknown>>;
}

type Register = (ceremony: Ceremony) => void;

/**
 * The key steps this plugin's settings screens run. The screens are in a
 * sandboxed frame, so Termix runs the browser prompt with these options and
 * sends the answer back here. Each answers `{ ok }` or `{ ok: false, error }`.
 */
export function registerCeremonies(
  ctx: PluginContext,
  repository: CredentialRepository,
  passkeys: PasskeyService,
  factor: FactorState,
): boolean {
  const register = (ctx.auth as { registerWebAuthnCeremony?: Register })
    .registerWebAuthnCeremony;
  if (typeof register !== "function") return false;
  const add = (ceremony: Ceremony) => register.call(ctx.auth, ceremony);

  add({
    id: "register",
    type: "create",
    options: async ({ userId, origin, extra }) => {
      const user = await findUser(ctx, "id", userId);
      if (!user) throw new Error("User not found");
      const { options, challengeId } = await passkeys.registrationOptions({
        userId: user.id,
        username: user.username,
        origin,
        userVerification: normalizeUserVerification(extra.userVerification),
      });
      return {
        publicKey: options as unknown as Record<string, unknown>,
        context: { challengeId },
      };
    },
    finish: async ({ userId, extra, context, response }) => {
      try {
        const result = await passkeys.register({
          userId,
          challengeId: context.challengeId,
          response: response as unknown as RegistrationResponseJSON,
          name: extra.name,
        });
        if (result === "expired") {
          return { ok: false, error: "Registration challenge expired" };
        }
        return result
          ? { ok: true }
          : { ok: false, error: "Passkey registration failed" };
      } catch (error) {
        ctx.log.warn(
          `Passkey registration failed for ${userId}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return { ok: false, error: "Passkey registration failed" };
      }
    },
  });

  // While the security key step is on, removing a key or turning the step
  // off needs a fresh tap, so a stolen session can't take it away.
  const proofOptions = async ({ userId }: { userId: string }) => {
    const options = await passkeys.factorOptions(userId);
    if (!options) throw new Error("No security key registered");
    return { publicKey: options as unknown as Record<string, unknown> };
  };
  const proved = (userId: string, response: Record<string, unknown>) =>
    passkeys.verifyFactor(userId, {
      response: response as unknown as AuthenticationResponseJSON,
    });

  add({
    id: "remove-key",
    type: "get",
    options: proofOptions,
    finish: async ({ userId, extra, response }) => {
      if (typeof extra.credentialId !== "string" || !extra.credentialId) {
        return { ok: false, error: "Pick a key to remove" };
      }
      if (!(await proved(userId, response))) {
        return { ok: false, error: "The security key check failed" };
      }
      await repository.deleteForUser(userId, extra.credentialId);
      // Without a key left the step could never pass, so it turns off.
      const left = await repository.listByUserId(userId);
      if (left.length === 0 && (await factor.isOn(userId))) {
        await factor.turnOff(userId);
      }
      return { ok: true };
    },
  });

  add({
    id: "disable-factor",
    type: "get",
    options: proofOptions,
    finish: async ({ userId, response }) => {
      if (!(await proved(userId, response))) {
        return { ok: false, error: "The security key check failed" };
      }
      await factor.turnOff(userId);
      return { ok: true };
    },
  });
  return true;
}
