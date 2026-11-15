import { eq } from "drizzle-orm";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Table = any;
type Drizzle = any;
/* eslint-enable @typescript-eslint/no-explicit-any */

export async function findUser(
  ctx: PluginContext,
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
