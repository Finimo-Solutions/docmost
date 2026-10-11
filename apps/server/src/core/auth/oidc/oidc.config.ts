import { EnvironmentService } from '../../../integrations/environment/environment.service';

/**
 * CuraIQ OIDC — first-party SSO module (community-safe, no EE license guard).
 *
 * Docmost ships SSO/OIDC only in its Enterprise-edition submodule behind a
 * license guard. This module lives in `core/auth` (always bundled) and gives
 * our fork native "Log in with CuraIQ" (Authentik) sign-in without the EE gate.
 *
 * Configured entirely by env so no secret is baked into the image:
 *   CURAIQ_OIDC_ENABLED        "true" to enable (also implicitly enabled if
 *                              issuer + client id + secret are all present)
 *   CURAIQ_OIDC_ISSUER         issuer identifier OR discovery URL, e.g.
 *                              https://auth.curaiq.net/application/o/docmost-oidc/
 *   CURAIQ_OIDC_CLIENT_ID
 *   CURAIQ_OIDC_CLIENT_SECRET
 *   CURAIQ_OIDC_SCOPES         default "openid email profile"
 *   CURAIQ_OIDC_BUTTON_LABEL   default "Log in with CuraIQ"
 *   CURAIQ_OIDC_REDIRECT_URI   default `${APP_URL}/api/auth/oidc/callback`
 *   CURAIQ_OIDC_AUTO_CREATE    "false" to reject unknown users (default true)
 */
export interface OidcConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  buttonLabel: string;
  redirectUri: string;
  autoCreate: boolean;
}

const DISCOVERY_SUFFIX = '/.well-known/openid-configuration';

/**
 * Normalise the configured issuer. openid-client v6 `discovery()` expects the
 * issuer identifier (it appends the well-known path itself), so if an operator
 * pasted the full discovery URL we strip the suffix.
 */
function normaliseIssuer(raw: string): string {
  const trimmed = (raw || '').trim();
  if (trimmed.endsWith(DISCOVERY_SUFFIX)) {
    return trimmed.slice(0, -DISCOVERY_SUFFIX.length);
  }
  return trimmed;
}

export function loadOidcConfig(env: EnvironmentService): OidcConfig {
  const issuer = normaliseIssuer(process.env.CURAIQ_OIDC_ISSUER || '');
  const clientId = (process.env.CURAIQ_OIDC_CLIENT_ID || '').trim();
  const clientSecret = (process.env.CURAIQ_OIDC_CLIENT_SECRET || '').trim();

  const hasCoreConfig = Boolean(issuer && clientId && clientSecret);
  const explicitFlag = String(process.env.CURAIQ_OIDC_ENABLED || '').toLowerCase();
  const enabled =
    explicitFlag === 'false'
      ? false
      : explicitFlag === 'true'
        ? hasCoreConfig
        : hasCoreConfig;

  const redirectUri =
    (process.env.CURAIQ_OIDC_REDIRECT_URI || '').trim() ||
    `${env.getAppUrl()}/api/auth/oidc/callback`;

  return {
    enabled,
    issuer,
    clientId,
    clientSecret,
    scopes: (process.env.CURAIQ_OIDC_SCOPES || 'openid email profile').trim(),
    buttonLabel: (process.env.CURAIQ_OIDC_BUTTON_LABEL || 'Log in with CuraIQ').trim(),
    redirectUri,
    autoCreate:
      String(process.env.CURAIQ_OIDC_AUTO_CREATE || 'true').toLowerCase() !== 'false',
  };
}
