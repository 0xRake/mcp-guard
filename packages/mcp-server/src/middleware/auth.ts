import { verify, sign, JWTPayload } from 'jsonwebtoken';
import { jwtVerify, SignJWT, importJWK } from 'jose';
import type { Request, Response, NextFunction } from '@modelcontextprotocol/sdk/types.js';

interface AuthConfig {
  enabled: boolean;
  secret?: string;
  publicKey?: string;
  algorithm?: 'HS256' | 'RS256' | 'ES256';
  issuer?: string;
  audience?: string;
  maxAge?: string;
}

export class AuthMiddleware {
  private config: AuthConfig;

  constructor(config: AuthConfig = { enabled: false }) {
    this.config = config;
  }

  async validateToken(token: string): Promise<JWTPayload | null> {
    if (!this.config.enabled) return null;

    try {
      if (this.config.algorithm === 'RS256' && this.config.publicKey) {
        // Use jose for RSA validation
        const publicKey = await importJWK(JSON.parse(this.config.publicKey));
        const { payload } = await jwtVerify(token, publicKey, {
          issuer: this.config.issuer,
          audience: this.config.audience,
        });
        return payload;
      } else if (this.config.secret) {
        // Use jsonwebtoken for HMAC validation
        return verify(token, this.config.secret, {
          algorithms: [this.config.algorithm || 'HS256'],
          issuer: this.config.issuer,
          audience: this.config.audience,
        }) as JWTPayload;
      }
    } catch (error) {
      console.error('Token validation failed:', error instanceof Error ? error.message : 'Unknown error');
      return null;
    }

    return null;
  }

  async generateToken(payload: Record<string, any>): Promise<string> {
    if (!this.config.enabled || !this.config.secret) {
      throw new Error('Auth not configured');
    }

    if (this.config.algorithm === 'RS256') {
      // Use jose for RSA signing
      const jwt = new SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setExpirationTime('2h');

      if (this.config.issuer) jwt.setIssuer(this.config.issuer);
      if (this.config.audience) jwt.setAudience(this.config.audience);

      // In production, would use private key
      throw new Error('RSA signing not configured');
    } else {
      // Use jsonwebtoken for HMAC signing
      return sign(payload, this.config.secret, {
        algorithm: this.config.algorithm || 'HS256',
        expiresIn: this.config.maxAge || '1h',
        issuer: this.config.issuer,
        audience: this.config.audience,
      });
    }
  }

  middleware() {
    return async (request: any, context: any, next: NextFunction) => {
      if (!this.config.enabled) {
        return next();
      }

      const authHeader = request.headers?.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Missing or invalid authorization header');
      }

      const token = authHeader.substring(7);
      const payload = await this.validateToken(token);

      if (!payload) {
        throw new Error('Invalid or expired token');
      }

      // Attach user context
      context.user = payload;
      return next();
    };
  }
}

export function createAuthMiddleware(config?: AuthConfig): AuthMiddleware {
  return new AuthMiddleware(config);
}