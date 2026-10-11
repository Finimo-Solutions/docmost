import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { EnvironmentService } from '../../../integrations/environment/environment.service';
import { SessionService } from '../../session/session.service';
import { SignupService } from '../services/signup.service';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { User } from '@docmost/db/types/entity.types';
import { isUserDisabled } from '../../../common/helpers';
import { loadOidcConfig, OidcConfig } from './oidc.config';

/**
 * openid-client v6 is ESM-only; we load it lazily via dynamic import so this
 * CommonJS NestJS build can consume it. The Configuration is memoised per
 * process (discovery document is stable).
 */
type OidcClientModule = typeof import('openid-client');

export interface OidcTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
}

const TX_TTL_MS = 10 * 60 * 1000; // 10 minutes to complete the round-trip

@Injectable()
export class OidcService {
  private readonly logger = new Logger(OidcService.name);
  private clientPromise: Promise<OidcClientModule> | null = null;
  private configPromise: Promise<any> | null = null;

  constructor(
    private readonly environmentService: EnvironmentService,
    private readonly sessionService: SessionService,
    private readonly signupService: SignupService,
    private readonly userRepo: UserRepo,
    private readonly workspaceRepo: WorkspaceRepo,
  ) {}

  getConfig(): OidcConfig {
    return loadOidcConfig(this.environmentService);
  }

  isEnabled(): boolean {
    return this.getConfig().enabled;
  }

  private async client(): Promise<OidcClientModule> {
    if (!this.clientPromise) {
      // eslint-disable-next-line @typescript-eslint/no-implied-eval
      this.clientPromise = (Function('return import("openid-client")')() as Promise<OidcClientModule>);
    }
    return this.clientPromise;
  }

  private async discovered(cfg: OidcConfig): Promise<any> {
    if (!this.configPromise) {
      const client = await this.client();
      this.configPromise = client
        .discovery(new URL(cfg.issuer), cfg.clientId, cfg.clientSecret)
        .catch((err) => {
          // don't cache a failed discovery — allow retry on next request
          this.configPromise = null;
          throw err;
        });
    }
    return this.configPromise;
  }

  /**
   * Build the Authentik authorization URL and return it together with the
   * transaction secrets the caller must stash in a cookie for the callback.
   */
  async buildAuthorization(): Promise<{ url: string; tx: OidcTransaction }> {
    const cfg = this.getConfig();
    if (!cfg.enabled) {
      throw new BadRequestException('CuraIQ SSO is not configured');
    }
    const client = await this.client();
    const config = await this.discovered(cfg);
    this.logger.log('OIDC buildAuthorization: starting login flow');

    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();
    const nonce = client.randomNonce();

    const url = client
      .buildAuthorizationUrl(config, {
        redirect_uri: cfg.redirectUri,
        scope: cfg.scopes,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        nonce,
      })
      .href;

    return { url, tx: { state, nonce, codeVerifier } };
  }

  /**
   * Exchange the callback for tokens, resolve the workspace, find-or-create the
   * user, and issue a Docmost session JWT (the value of the `authToken` cookie).
   */
  async handleCallback(
    currentUrl: string,
    tx: OidcTransaction,
  ): Promise<string> {
    const cfg = this.getConfig();
    if (!cfg.enabled) {
      throw new BadRequestException('CuraIQ SSO is not configured');
    }
    const client = await this.client();
    const config = await this.discovered(cfg);

    const tokens = await client.authorizationCodeGrant(
      config,
      new URL(currentUrl),
      {
        pkceCodeVerifier: tx.codeVerifier,
        expectedState: tx.state,
        expectedNonce: tx.nonce,
      },
    );

    const claims: Record<string, any> = tokens.claims() ?? {};
    let email = typeof claims.email === 'string' ? claims.email : undefined;
    let name =
      typeof claims.name === 'string'
        ? claims.name
        : typeof (claims as any).preferred_username === 'string'
          ? (claims as any).preferred_username
          : undefined;

    // Fall back to the userinfo endpoint if the id_token omitted email/name.
    if (!email || !name) {
      try {
        const info = await client.fetchUserInfo(
          config,
          tokens.access_token,
          claims.sub as string,
        );
        email = email || (typeof info.email === 'string' ? info.email : undefined);
        name =
          name ||
          (typeof info.name === 'string' ? info.name : undefined) ||
          (typeof info.preferred_username === 'string'
            ? info.preferred_username
            : undefined);
      } catch (err) {
        this.logger.warn(`userinfo fetch failed: ${(err as any)?.message ?? err}`);
      }
    }

    if (!email) {
      throw new UnauthorizedException(
        'CuraIQ SSO did not return an email claim',
      );
    }
    email = email.toLowerCase();

    const workspace = await this.workspaceRepo.findFirst();
    if (!workspace) {
      throw new BadRequestException('No workspace has been set up yet');
    }

    let user = await this.userRepo.findByEmail(email, workspace.id);
    this.logger.log(
      `OIDC callback: email=${email} existing=${!!user} ws=${workspace.id}`,
    );

    if (!user) {
      if (!cfg.autoCreate) {
        throw new UnauthorizedException(
          'No Docmost account exists for this CuraIQ user',
        );
      }
      this.logger.log(`OIDC auto-provisioning new user: ${email}`);
      user = await this.signupService.signup(
        {
          name: name || email.split('@')[0],
          email,
          // OIDC users never log in by password; store a random unusable one.
          password: crypto.randomBytes(24).toString('base64url'),
        },
        workspace.id,
      );
    }

    if (isUserDisabled(user)) {
      throw new UnauthorizedException('This account is disabled');
    }

    await this.userRepo.updateLastLogin(user.id, workspace.id);

    return this.sessionService.createSessionAndToken(user as User);
  }

  // --- transaction cookie signing (HMAC over app secret; no new dependency) ---

  signTransaction(tx: OidcTransaction): string {
    const payload = { ...tx, exp: Date.now() + TX_TTL_MS };
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const mac = this.mac(body);
    return `${body}.${mac}`;
  }

  verifyTransaction(cookie: string | undefined): OidcTransaction {
    if (!cookie || !cookie.includes('.')) {
      throw new UnauthorizedException('Missing SSO transaction');
    }
    const [body, mac] = cookie.split('.', 2);
    const expected = this.mac(body);
    if (
      mac.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))
    ) {
      throw new UnauthorizedException('Invalid SSO transaction');
    }
    let payload: OidcTransaction & { exp: number };
    try {
      payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch {
      throw new UnauthorizedException('Malformed SSO transaction');
    }
    if (!payload.exp || payload.exp < Date.now()) {
      throw new UnauthorizedException('Expired SSO transaction');
    }
    return {
      state: payload.state,
      nonce: payload.nonce,
      codeVerifier: payload.codeVerifier,
    };
  }

  private mac(body: string): string {
    return crypto
      .createHmac('sha256', this.environmentService.getAppSecret())
      .update(body)
      .digest('base64url');
  }
}
