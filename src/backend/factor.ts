import { eq } from "drizzle-orm";
import type {
  PluginContext,
  PluginDatabase,
} from "@termix-ssh/plugin-sdk/backend";

export const SECURITY_KEY_FACTOR = "security-key";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Table = any;
type Drizzle = any;
/* eslint-enable @typescript-eslint/no-explicit-any */

export type FactorState = ReturnType<typeof createFactorState>;

/** Whether a user asked for their key after the password. */
export function createFactorState(
  ctx: PluginContext,
  db: PluginDatabase,
  table: Table,
) {
  const client = () => db.client<Drizzle>();
  const remove = async (userId: string) => {
    const drizzle = await client();
    await drizzle.delete(table).where(eq(table.userId, userId));
    await db.persist();
  };

  return {
    async isOn(userId: string): Promise<boolean> {
      const drizzle = await client();
      const rows = await drizzle
        .select()
        .from(table)
        .where(eq(table.userId, userId))
        .limit(1);
      return rows.length > 0;
    },

    /** Core's policy first, so a refusal leaves nothing half on. */
    async turnOn(userId: string): Promise<void> {
      await ctx.auth.recordEnrollment(userId, SECURITY_KEY_FACTOR);
      if (await this.isOn(userId)) return;
      const drizzle = await client();
      await drizzle
        .insert(table)
        .values({ userId, enabledAt: new Date().toISOString() });
      await db.persist();
    },

    async turnOff(userId: string): Promise<void> {
      await ctx.auth.removeEnrollment(userId, SECURITY_KEY_FACTOR);
      await remove(userId);
    },

    clear: remove,
  };
}
