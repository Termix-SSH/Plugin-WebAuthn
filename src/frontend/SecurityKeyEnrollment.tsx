import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@termix-ssh/plugin-sdk/ui";
import { usePluginApi, useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import { createWebAuthnApi } from "./webauthn-api";

function apiErrorMessage(error: unknown, fallback: string): string {
  const data = (error as { response?: { data?: { error?: unknown } } })
    ?.response?.data;
  return typeof data?.error === "string" && data.error ? data.error : fallback;
}

/** Settings > Security: ask for a key after the password, or stop asking. */
export function SecurityKeyEnrollment() {
  const { t } = useTranslation();
  const pluginApi = usePluginApi();
  const api = useMemo(() => createWebAuthnApi(pluginApi), [pluginApi]);
  const [status, setStatus] = useState<{ enabled: boolean; keys: number }>();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api
      .factorStatus()
      .then(setStatus)
      .catch(() => {});
  }, [api]);

  async function change(enabled: boolean) {
    setLoading(true);
    try {
      // With no key yet, adding one comes first.
      if (enabled && status?.keys === 0) {
        await api.register(t("securityKey.keyName"), "discouraged");
      }
      await api.setFactor(enabled);
      setStatus(await api.factorStatus());
      toast.success(
        t(enabled ? "securityKey.turnedOn" : "securityKey.turnedOff"),
      );
    } catch (e) {
      const name = (e as { name?: string })?.name;
      if (name !== "NotAllowedError" && name !== "AbortError") {
        toast.error(apiErrorMessage(e, t("securityKey.saveFailed")));
      }
    } finally {
      setLoading(false);
    }
  }

  if (!status) return null;
  return (
    <div className="flex flex-col gap-2">
      <span className="text-[10px] text-muted-foreground">
        {t("securityKey.description")}
      </span>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs">
          {status.enabled ? t("securityKey.on") : t("securityKey.off")}
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={loading}
          onClick={() => void change(!status.enabled)}
        >
          {status.enabled
            ? t("securityKey.turnOff")
            : status.keys === 0
              ? t("securityKey.addKey")
              : t("securityKey.turnOn")}
        </Button>
      </div>
    </div>
  );
}
