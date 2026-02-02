/**
 * Authentication Manager
 * @module auth/manager
 *
 * Manages authentication with the relayer.
 */

import bs58 from 'bs58';
import { ConsoleLogger } from '../logger/console.js';

const logger = new ConsoleLogger({ prefix: '[Mink:Auth]', minLevel: 'info' });

/**
 * Message signer function type
 */
export type MessageSigner = (message: Uint8Array) => Promise<Uint8Array>;

/**
 * Auth token data
 */
export interface AuthTokenData {
  token: string;
  expiresAt: number;
  walletAddress: string;
}

/**
 * Auth manager configuration
 */
export interface AuthManagerConfig {
  relayerUrl: string;
  onAuthenticated?: () => void;
  onExpired?: () => void;
}

/**
 * Authentication Manager
 *
 * Handles authentication with the relayer using wallet signatures.
 */
export class AuthManager {
  private relayerUrl: string;
  private tokenData: AuthTokenData | null = null;
  private onAuthenticated?: () => void;
  private onExpired?: () => void;
  private refreshTimer?: ReturnType<typeof setTimeout>;

  constructor(config: AuthManagerConfig) {
    this.relayerUrl = config.relayerUrl;
    this.onAuthenticated = config.onAuthenticated;
    this.onExpired = config.onExpired;
  }

  /**
   * Check if currently authenticated
   */
  isAuthenticated(): boolean {
    if (!this.tokenData) return false;
    return Date.now() < this.tokenData.expiresAt;
  }

  /**
   * Get current auth token
   */
  getToken(): string | null {
    if (!this.isAuthenticated()) return null;
    return this.tokenData?.token ?? null;
  }

  /**
   * Authenticate with the relayer
   *
   * @param signMessage - Wallet sign message function
   * @param walletAddress - Wallet public key (base58)
   * @returns True if authenticated successfully
   */
  async authenticate(
    signMessage: MessageSigner,
    walletAddress: string
  ): Promise<boolean> {
    try {
      logger.info(`Starting authentication for ${walletAddress}`);
      logger.info(`Relayer URL: ${this.relayerUrl}`);

      // Get challenge from relayer
      logger.info('Fetching challenge from relayer...');
      const challengeResponse = await fetch(`${this.relayerUrl}/auth/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletAddress }),
      });

      logger.info(`Challenge response status: ${challengeResponse.status}`);

      if (!challengeResponse.ok) {
        const errorText = await challengeResponse.text();
        logger.error(`Failed to get auth challenge: ${errorText}`);
        return false;
      }

      const challengeJson = await challengeResponse.json() as Record<string, unknown>;
      logger.info('Challenge response:', JSON.stringify(challengeJson).substring(0, 200));

      // Handle SIWS format: { success: true, data: { message: ..., nonce: ... } }
      const challengeData = (challengeJson.data as Record<string, unknown>) ?? challengeJson;
      const siwsMessage = (challengeData.message ?? challengeData.challenge) as string;
      const nonce = challengeData.nonce as string;

      if (!siwsMessage) {
        logger.error('No message/challenge in response');
        return false;
      }

      logger.info(`Got SIWS message, nonce: ${nonce}`);

      // Sign the SIWS message
      logger.info('Requesting wallet signature...');
      const messageBytes = new TextEncoder().encode(siwsMessage);
      const signature = await signMessage(messageBytes);
      logger.info(`Got signature, length: ${signature.length}`);

      // Submit signature to get token (use base58 encoding for Solana)
      const signatureBase58 = bs58.encode(signature);
      logger.info('Verifying signature with relayer...');
      logger.info(`Signature (base58): ${signatureBase58.substring(0, 20)}...`);

      const tokenResponse = await fetch(`${this.relayerUrl}/auth/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletAddress,
          message: siwsMessage,
          signature: signatureBase58,
        }),
      });

      logger.info(`Verify response status: ${tokenResponse.status}`);

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        logger.error(`Failed to verify signature: ${errorText}`);
        return false;
      }

      const verifyJson = await tokenResponse.json() as Record<string, unknown>;
      logger.info('Verify response:', JSON.stringify(verifyJson).substring(0, 200));

      // Handle both formats: { token: ... } or { success: true, data: { accessToken: ..., expiresIn: ... } }
      const verifyData = (verifyJson.data as Record<string, unknown>) ?? verifyJson;
      const token = (verifyData.accessToken ?? verifyData.token ?? verifyData.jwt) as string;

      // Parse expiration - can be expiresIn (seconds), expiresAt (timestamp), or exp (JWT)
      let tokenExpiresAt: number;
      const expiresIn = verifyData.expiresIn as number | undefined;
      const expiresAtRaw = verifyData.expiresAt ?? verifyData.exp;

      if (typeof expiresIn === 'number') {
        // expiresIn is in seconds - convert to absolute timestamp
        tokenExpiresAt = Date.now() + expiresIn * 1000;
        logger.info(`Token expires in ${expiresIn} seconds`);
      } else if (typeof expiresAtRaw === 'string') {
        tokenExpiresAt = new Date(expiresAtRaw).getTime();
      } else if (typeof expiresAtRaw === 'number') {
        // Could be seconds (JWT exp) or milliseconds
        tokenExpiresAt = expiresAtRaw < 1e12 ? expiresAtRaw * 1000 : expiresAtRaw;
      } else {
        tokenExpiresAt = Date.now() + 15 * 60 * 1000; // Default 15 minutes
      }

      if (!token) {
        logger.error('No token in response. Keys found:', Object.keys(verifyData));
        return false;
      }

      this.tokenData = {
        token,
        expiresAt: tokenExpiresAt,
        walletAddress,
      };

      // Schedule refresh before expiry
      this.scheduleRefresh();

      logger.info('Authentication successful');
      this.onAuthenticated?.();
      return true;
    } catch (error) {
      logger.error('Authentication failed:', error);
      return false;
    }
  }

  /**
   * Logout and clear auth state
   */
  logout(): void {
    this.tokenData = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = undefined;
    }
    logger.info('Logged out');
  }

  /**
   * Dispose of the auth manager
   */
  dispose(): void {
    this.logout();
  }

  /**
   * Schedule token refresh
   */
  private scheduleRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!this.tokenData) return;

    // Refresh 5 minutes before expiry
    const refreshIn = Math.max(0, this.tokenData.expiresAt - Date.now() - 5 * 60 * 1000);

    this.refreshTimer = setTimeout(() => {
      this.tokenData = null;
      this.onExpired?.();
    }, refreshIn);
  }
}
