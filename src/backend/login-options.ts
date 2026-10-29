import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";

/** Passwordless passkey sign in, on unless an admin turned it off. */
export async function passwordlessEnabled(
  ctx: Pick<PluginContext, "settings">,
): Promise<boolean> {
  try {
    return (await ctx.settings.get<boolean>("passwordlessLogin")) !== false;
  } catch {
    return true;
  }
}
