import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './services/auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { WorkspaceModule } from '../workspace/workspace.module';
import { SignupService } from './services/signup.service';
import { TokenModule } from './token.module';
import { OidcController } from './oidc/oidc.controller';
import { OidcService } from './oidc/oidc.service';

@Module({
  imports: [TokenModule, WorkspaceModule],
  controllers: [AuthController, OidcController],
  providers: [AuthService, SignupService, JwtStrategy, OidcService],
  exports: [SignupService],
})
export class AuthModule {}
