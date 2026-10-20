import type { Request, Response, Router } from "express";
import { eq } from "drizzle-orm";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import {
  LoginMethodError,
  type PluginContext,
} from "@termix-ssh/plugin-sdk/backend";
import type { FactorState } from "./factor.js";
import {
  normalizeUserVerification,
  parseTransports,
  requestOrigin,
  type PasskeyService,
} from "./passkeys.js";
import type { CredentialRepository } from "./repository.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Table = any;
type Drizzle = any;
/* eslint-enable @typescript-eslint/no-explicit-any */

export const PUBLIC_PATHS = ["/authenticate/options"];

export function registerPasskeyRoutes(
  router: Router,
  ctx: PluginContext,
  repository: CredentialRepository,
  passkeys: PasskeyService,
  factor: FactorState,
): void {
  async function findUser(
    column: "id" | "username",
    value: string,
  ): Promise<{ id: string; username: string } | null> {
    const { users } = await ctx.db.refs<{ users: Table }>();
    const drizzle = await ctx.db.client<Drizzle>();
    const rows = await drizzle
      .select({ id: users.id, username: users.username })
      .from(users)
      .where(eq(users[column], value))
      .limit(1);
    return rows[0] ?? null;
  }

  /**
   * @openapi
   * /plugin-api/webauthn/credentials:
   *   get:
   *     summary: List passkeys
   *     description: Lists the caller's registered passkeys.
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: List of passkeys.
   */
  router.get("/credentials", async (_req: Request, res: Response) => {
    const credentials = await repository.listByUserId(ctx.currentActor()!);
    res.json({
      credentials: credentials.map((credential) => ({
        id: credential.id,
        name: credential.name,
        deviceType: credential.deviceType,
        backedUp: !!credential.backedUp,
        transports: parseTransports(credential.transports),
        userVerification: credential.userVerification,
        createdAt: credential.createdAt,
        lastUsedAt: credential.lastUsedAt,
      })),
    });
  });

  /**
   * @openapi
   * /plugin-api/webauthn/register/options:
   *   post:
   *     summary: Start passkey registration
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: Registration options and challenge id.
   *       404:
   *         description: User not found.
   */
  router.post("/register/options", async (req: Request, res: Response) => {
    const user = await findUser("id", ctx.currentActor()!);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(
      await passkeys.registrationOptions({
        userId: user.id,
        username: user.username,
        origin: requestOrigin(req.headers),
        userVerification: normalizeUserVerification(req.body?.userVerification),
      }),
    );
  });

  /**
   * @openapi
   * /plugin-api/webauthn/register/verify:
   *   post:
   *     summary: Finish passkey registration
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: Passkey registered.
   *       400:
   *         description: Registration failed or challenge expired.
   */
  router.post("/register/verify", async (req: Request, res: Response) => {
    const userId = ctx.currentActor()!;
    try {
      const result = await passkeys.register({
        userId,
        challengeId: req.body?.challengeId,
        response: req.body?.response as RegistrationResponseJSON | undefined,
        name: req.body?.name,
      });
      if (result === "expired") {
        return res
          .status(400)
          .json({ error: "Registration challenge expired" });
      }
      if (!result) {
        return res.status(400).json({ error: "Passkey registration failed" });
      }
      res.json({ success: true });
    } catch (error) {
      ctx.log.warn(
        `Passkey registration failed for ${userId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      res.status(400).json({ error: "Passkey registration failed" });
    }
  });

  /**
   * @openapi
   * /plugin-api/webauthn/authenticate/options:
   *   post:
   *     summary: Start passkey login
   *     description: Public. Authentication options, optionally scoped to a username. The assertion is then sent to /users/auth/passkey/verify.
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: Authentication options and challenge id.
   *       404:
   *         description: No passkeys found for the user.
   */
  router.post("/authenticate/options", async (req: Request, res: Response) => {
    const username =
      typeof req.body?.username === "string" ? req.body.username.trim() : "";
    let userId: string | undefined;
    if (username) {
      const user = await findUser("username", username);
      if (!user) return res.status(404).json({ error: "No passkeys found" });
      userId = user.id;
    }
    const result = await passkeys.authenticationOptions({
      userId,
      origin: requestOrigin(req.headers),
      userVerification: normalizeUserVerification(req.body?.userVerification),
    });
    if (!result) return res.status(404).json({ error: "No passkeys found" });
    res.json(result);
  });

  /**
   * @openapi
   * /plugin-api/webauthn/credentials/{credentialId}:
   *   delete:
   *     summary: Delete a passkey
   *     tags:
   *       - Passkeys
   *     parameters:
   *       - in: path
   *         name: credentialId
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       200:
   *         description: Passkey deleted.
   */
  router.delete(
    "/credentials/:credentialId",
    async (req: Request, res: Response) => {
      const userId = ctx.currentActor()!;
      await repository.deleteForUser(userId, String(req.params.credentialId));
      // Without a key left the step could never pass, so it turns off.
      const left = await repository.listByUserId(userId);
      if (left.length === 0 && (await factor.isOn(userId))) {
        await factor.turnOff(userId);
      }
      res.json({ success: true });
    },
  );

  /**
   * @openapi
   * /plugin-api/webauthn/second-factor:
   *   get:
   *     summary: Security key step status
   *     description: Whether the caller is asked for a security key after their password, and how many keys they have.
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: Status.
   */
  router.get("/second-factor", async (_req: Request, res: Response) => {
    const userId = ctx.currentActor()!;
    const keys = await repository.listByUserId(userId);
    res.json({ enabled: await factor.isOn(userId), keys: keys.length });
  });

  /**
   * @openapi
   * /plugin-api/webauthn/second-factor/enable:
   *   post:
   *     summary: Ask for a security key after the password
   *     description: Needs at least one registered key. Signs the caller out everywhere else.
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: Turned on.
   *       400:
   *         description: No key registered.
   *       409:
   *         description: Second factors are turned off on this server.
   */
  router.post("/second-factor/enable", async (_req: Request, res: Response) => {
    const userId = ctx.currentActor()!;
    const keys = await repository.listByUserId(userId);
    if (keys.length === 0) {
      return res.status(400).json({ error: "Add a security key first" });
    }
    try {
      await factor.turnOn(userId);
    } catch (error) {
      if (error instanceof LoginMethodError) {
        return res.status(error.status).json({ error: error.message });
      }
      throw error;
    }
    res.json({ enabled: true });
  });

  /**
   * @openapi
   * /plugin-api/webauthn/second-factor/disable:
   *   post:
   *     summary: Stop asking for a security key after the password
   *     tags:
   *       - Passkeys
   *     responses:
   *       200:
   *         description: Turned off.
   */
  router.post(
    "/second-factor/disable",
    async (_req: Request, res: Response) => {
      await factor.turnOff(ctx.currentActor()!);
      res.json({ enabled: false });
    },
  );
}
