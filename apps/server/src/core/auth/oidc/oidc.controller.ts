import { Controller, Get, Logger, Req, Res } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { FastifyReply, FastifyRequest } from 'fastify';
import { EnvironmentService } from '../../../integrations/environment/environment.service';
import { SkipTransform } from '../../../common/decorators/skip-transform.decorator';
import { OidcService } from './oidc.service';

const TX_COOKIE = 'curaiq_oidc_tx';
// Cookie is only ever read by the callback route.
const TX_COOKIE_PATH = '/api/auth/oidc';

@SkipThrottle()
@Controller('auth/oidc')
export class OidcController {
  private readonly logger = new Logger(OidcController.name);

  constructor(
    private readonly oidcService: OidcService,
    private readonly environmentService: EnvironmentService,
  ) {}

  /** Public flag the client login page reads to decide whether to show the button. */
  @SkipTransform()
  @Get('config')
  config() {
    const cfg = this.oidcService.getConfig();
    return { enabled: cfg.enabled, buttonLabel: cfg.buttonLabel };
  }

  /** Kick off the flow: build the Authentik URL, stash the transaction, redirect. */
  @SkipTransform()
  @Get('login')
  async login(@Res() res: FastifyReply) {
    const { url, tx } = await this.oidcService.buildAuthorization();

    res.setCookie(TX_COOKIE, this.oidcService.signTransaction(tx), {
      httpOnly: true,
      // Lax so the cookie IS sent on the top-level redirect back from Authentik
      // (the exact failure mode that broke better-auth on Documenso).
      sameSite: 'lax',
      secure: this.environmentService.isHttps(),
      path: TX_COOKIE_PATH,
      maxAge: 600, // seconds
    });

    res.status(302).redirect(url);
  }

  /** Handle the return from Authentik: verify, exchange, issue a Docmost session. */
  @SkipTransform()
  @Get('callback')
  async callback(@Req() req: FastifyRequest, @Res() res: FastifyReply) {
    const appUrl = this.environmentService.getAppUrl();
    try {
      const tx = this.oidcService.verifyTransaction(
        (req as any).cookies?.[TX_COOKIE],
      );
      const currentUrl = `${appUrl}${req.url}`;
      const authToken = await this.oidcService.handleCallback(currentUrl, tx);

      res.clearCookie(TX_COOKIE, { path: TX_COOKIE_PATH });
      res.setCookie('authToken', authToken, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        expires: this.environmentService.getCookieExpiresIn(),
        secure: this.environmentService.isHttps(),
      });

      res.status(302).redirect(appUrl + '/home');
    } catch (err) {
      this.logger.error(`OIDC callback failed: ${(err as any)?.message ?? err}`);
      res.clearCookie(TX_COOKIE, { path: TX_COOKIE_PATH });
      res.status(302).redirect(appUrl + '/login?error=sso');
    }
  }
}
