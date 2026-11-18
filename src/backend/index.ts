import type { Router } from "express";
import {
  LoginMethodError,
  type PluginContext,
} from "@termix-ssh/plugin-sdk/backend";
import { credentials, factors } from "./tables.js";
import { createCredentialRepository } from "./repository.js";
import {
  createPasskeyService,
  normalizeUserVerification,
  requestOrigin,
} from "./passkeys.js";
import { PUBLIC_PATHS, registerPasskeyRoutes } from "./routes.js";
import { SECURITY_KEY_FACTOR, createFactorState } from "./factor.js";
import { passkeysOnSsoPage, passwordlessEnabled } from "./login-options.js";
import { registerCeremonies } from "./ceremonies.js";
import { findUser } from "./users.js";

export async function activate(ctx: PluginContext) {
  const table = await ctx.db.define(credentials);
  const repository = createCredentialRepository(ctx.db, table);
  const passkeys = createPasskeyService(ctx, repository);

  // Termix draws the button and runs the browser prompt with these options.
  // A passkey method never counts for the password lockout guard, since it
  // only helps a user who already registered one.
  ctx.auth.registerLoginMethod({
    id: "passkey",
    labelKey: "signIn",
    icon: "fingerprint",
    kind: "webauthn",
    placement: "inline",
    describe: async () => [
      {
        id: "passkey",
        label: "Passkey",
        enabled: await passwordlessEnabled(ctx),
        ...((await passkeysOnSsoPage(ctx))
          ? {}
          : { views: ["password" as const] }),
      },
    ],
    options: async (request) => {
      if (!(await passwordlessEnabled(ctx))) {
        throw new LoginMethodError("Passkey sign in is turned off", 403);
      }
      const username =
        typeof request.body?.username === "string"
          ? request.body.username.trim()
          : "";
      let userId: string | undefined;
      if (username) {
        const user = await findUser(ctx, "username", username);
        if (!user) throw new LoginMethodError("No passkeys found", 404);
        userId = user.id;
      }
      const result = await passkeys.authenticationOptions({
        userId,
        origin: requestOrigin(request.headers),
        userVerification: normalizeUserVerification(
          request.body?.userVerification,
        ),
      });
      if (!result) throw new LoginMethodError("No passkeys found", 404);
      return {
        publicKey: result.options as unknown as Record<string, unknown>,
        context: { challengeId: result.challengeId },
      };
    },
    verify: async (request) => {
      if (!(await passwordlessEnabled(ctx))) {
        throw new LoginMethodError("Passkey sign in is turned off", 403);
      }
      return passkeys.verifyLogin(request.body ?? {});
    },
  });

  // A key as the step after a password. Each user turns it on, so a passkey
  // kept only for passwordless sign in never adds a step.
  const factor = createFactorState(ctx, ctx.db, await ctx.db.define(factors));
  ctx.auth.registerSecondFactor({
    id: SECURITY_KEY_FACTOR,
    labelKey: "securityKey.title",
    prompt: { kind: "webauthn" },
    isEnrolled: (userId) => factor.isOn(userId),
    challenge: async (userId) => passkeys.factorOptions(userId),
    verify: (userId, body) => passkeys.verifyFactor(userId, body),
    reset: (userId) => factor.clear(userId),
  });

  registerCeremonies(ctx, repository, passkeys, factor);

  registerPasskeyRoutes(
    ctx.http.router<Router>({ public: PUBLIC_PATHS }),
    ctx,
    repository,
    passkeys,
    factor,
  );
}

export async function deactivate() {
  // Everything above was registered through ctx and is disposed by core.
}
