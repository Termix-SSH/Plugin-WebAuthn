import type { Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { credentials, factors } from "./tables.js";
import { createCredentialRepository } from "./repository.js";
import { createPasskeyService } from "./passkeys.js";
import { PUBLIC_PATHS, registerPasskeyRoutes } from "./routes.js";
import { SECURITY_KEY_FACTOR, createFactorState } from "./factor.js";

export async function activate(ctx: PluginContext) {
  const table = await ctx.db.define(credentials);
  const repository = createCredentialRepository(ctx.db, table);
  const passkeys = createPasskeyService(ctx, repository);

  // No describe: a passkey only helps a user who already registered one, so
  // it never counts for the password lockout guard.
  ctx.auth.registerLoginMethod({
    id: "passkey",
    labelKey: "signIn",
    icon: "fingerprint",
    kind: "form",
    verify: (request) => passkeys.verifyLogin(request.body ?? {}),
  });

  // A key as the step after a password. Each user turns it on, so a passkey
  // kept only for passwordless sign in never adds a step.
  const factor = createFactorState(ctx, ctx.db, await ctx.db.define(factors));
  ctx.auth.registerSecondFactor({
    id: SECURITY_KEY_FACTOR,
    labelKey: "securityKey.title",
    isEnrolled: (userId) => factor.isOn(userId),
    challenge: async (userId) => passkeys.factorOptions(userId),
    verify: (userId, body) => passkeys.verifyFactor(userId, body),
    reset: (userId) => factor.clear(userId),
  });

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
