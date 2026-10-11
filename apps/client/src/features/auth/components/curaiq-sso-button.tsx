import { useEffect, useState } from "react";
import { Button, Divider } from "@mantine/core";

/**
 * CuraIQ SSO button — first-party fork addition.
 *
 * Renders "Log in with CuraIQ" only when the backend reports OIDC is enabled
 * (GET /api/auth/oidc/config). Clicking it starts the server-driven OIDC flow
 * at /api/auth/oidc/login. Kept dependency-free (plain fetch, same origin) so
 * it survives upstream rebases with no coupling to the EE SSO components.
 */
export default function CuraiqSsoButton() {
  const [enabled, setEnabled] = useState(false);
  const [label, setLabel] = useState("Log in with CuraIQ");

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/oidc/config", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg) => {
        if (cancelled || !cfg?.enabled) return;
        setEnabled(true);
        if (cfg.buttonLabel) setLabel(cfg.buttonLabel);
      })
      .catch(() => {
        /* SSO simply stays hidden if the probe fails */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!enabled) return null;

  return (
    <>
      <Button
        component="a"
        href="/api/auth/oidc/login"
        variant="default"
        fullWidth
        mb="md"
      >
        {label}
      </Button>
      <Divider label="or" labelPosition="center" my="md" />
    </>
  );
}
