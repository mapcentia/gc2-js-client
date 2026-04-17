/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import {jwtDecode} from './jwt-decode'
import {Gc2Service} from "../services/gc2.services"
import {getStorage} from './storage'

export type Tokens = {
    accessToken: string
    refreshToken: string
    idToken?: string
}

export type Options = {
    host: string
    wsHost?: string
    tokenUri?: string
    authUri?: string
    logoutUri?: string
    deviceUri?: string
    scope?: string
    clientId: string
    clientSecret?: string
}

export type CodeFlowOptions = Options & {
    redirectUri: string
}

export type PasswordFlowOptions = Options & {
    username: string
    password: string
    database: string
}

export type SignUpOptions = Options & {
    host: string
    clientId: string
    parentDb: string
    redirectUri: string
}

export type GetDeviceCodeResponse = {
    device_code: string
    user_code: string
    verification_uri: string
    verification_uri_complete?: string
    expires_in: number
    interval: number
}

export type GetTokenResponse = {
    access_token: string
    expires_in: number
    refresh_expires_in: number
    refresh_token: string
    id_token?: string
    token_type: string
    'not-before-policy': number
    session_state: string
    scope: string
}


export const generatePkceChallenge = async () => {

    const generateRandomString = () => {
        const array = new Uint32Array(28);
        if (globalThis.crypto?.getRandomValues) {
            crypto.getRandomValues(array);
        } else {
            for (let i = 0; i < array.length; i++) {
                array[i] = (Math.random() * 0xFFFFFFFF) >>> 0;
            }
        }
        return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
    }

    const sha256 = async (plain: string | undefined): Promise<ArrayBuffer> => {
        const encoder = new TextEncoder();
        const data = encoder.encode(plain);
        if (globalThis.crypto?.subtle) {
            return crypto.subtle.digest('SHA-256', data);
        }
        return sha256Fallback(data);
    }

    const base64urlEncode = (str: ArrayBuffer) => {

        return btoa(String.fromCharCode.apply(null, [...new Uint8Array(str)]))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function pkceChallengeFromVerifier(v: string | undefined) {
        const hashed = await sha256(v);
        return base64urlEncode(hashed);
    }

    const {state, codeVerifier} = {
        state: generateRandomString(),
        codeVerifier: generateRandomString(),
    };
    const codeChallenge = await pkceChallengeFromVerifier(codeVerifier);

    return {
        state,
        codeVerifier,
        codeChallenge,
    }
}

/**
 * Pure JS SHA-256 fallback for insecure contexts (HTTP) where crypto.subtle is unavailable.
 */
const sha256Fallback = (data: Uint8Array): ArrayBuffer => {
    const K: number[] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    const rotr = (n: number, x: number) => (x >>> n) | (x << (32 - n));
    const ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);
    const maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);
    const sigma0 = (x: number) => rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
    const sigma1 = (x: number) => rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
    const gamma0 = (x: number) => rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
    const gamma1 = (x: number) => rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);

    // Pre-processing: padding
    const bitLen = data.length * 8;
    const padded: number[] = Array.from(data);
    padded.push(0x80);
    while ((padded.length % 64) !== 56) padded.push(0);
    // Append 64-bit big-endian bit length
    for (let i = 56; i >= 0; i -= 8) {
        padded.push(i >= 32 ? 0 : (bitLen >>> i) & 0xff);
    }

    // Initial hash values
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // Process each 512-bit block
    for (let offset = 0; offset < padded.length; offset += 64) {
        const W: number[] = new Array(64);
        for (let i = 0; i < 16; i++) {
            W[i] = (padded[offset + i * 4] << 24) | (padded[offset + i * 4 + 1] << 16) |
                (padded[offset + i * 4 + 2] << 8) | padded[offset + i * 4 + 3];
        }
        for (let i = 16; i < 64; i++) {
            W[i] = (gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16]) | 0;
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        for (let i = 0; i < 64; i++) {
            const t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + W[i]) | 0;
            const t2 = (sigma0(a) + maj(a, b, c)) | 0;
            h = g; g = f; f = e; e = (d + t1) | 0;
            d = c; c = b; b = a; a = (t1 + t2) | 0;
        }

        h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
        h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }

    const result = new ArrayBuffer(32);
    const view = new DataView(result);
    view.setUint32(0, h0); view.setUint32(4, h1); view.setUint32(8, h2); view.setUint32(12, h3);
    view.setUint32(16, h4); view.setUint32(20, h5); view.setUint32(24, h6); view.setUint32(28, h7);
    return result;
}

export const isTokenExpired = (token: string): boolean => {
    let isJwtExpired = false
    const {exp} = jwtDecode(token)
    const currentTime = new Date().getTime() / 1000

    if (exp) {
        if (currentTime > exp) isJwtExpired = true
    }
    return isJwtExpired
}

export const claims = (token: string): any => {
    return jwtDecode(token)
}

export const passwordIsStrongEnough = (password: string, allowNull: boolean = false) => {
    const message = 'Entered password is too weak'
    if (password === '' && allowNull) return true
    if (password.length < 8) return message
    if (!(/[A-Z]/.test(password))) return message
    if (!(/[a-z]/.test(password))) return message
    if (!(/\d/.test(password))) return message
    return true
}

export const isLogin = async (gc2: Gc2Service): Promise<boolean> => {
    const {accessToken, refreshToken} = getTokens()
    if (!accessToken && !refreshToken) {
        return false
    }
    if (!accessToken || (accessToken && isTokenExpired(accessToken))) {
        if (refreshToken && isTokenExpired(refreshToken)) {
            clearTokens()
            clearOptions()
            throw new Error('Refresh token has expired. Please login again.')
        }
        if (refreshToken) {
            try {
                const data = await gc2.getRefreshToken(refreshToken)
                setTokens({accessToken: data.access_token, refreshToken, idToken: data?.id_token})
                console.log('Access token refreshed')
            } catch (e) {
                throw new Error('Could not get refresh token.')
            }
        }
    }
    return true
}

export const setTokens = (tokens: Tokens): void => {
    getStorage().setItem('gc2_tokens', JSON.stringify({
                'accessToken': tokens.accessToken,
                'refreshToken': tokens.refreshToken,
                'idToken': tokens?.idToken || ''
            }
        )
    )
}

export const getTokens = (): Tokens => {
    const str: string | null = getStorage().getItem('gc2_tokens')
    const tokens: any = str ? JSON.parse(str) : {}
    return {
        accessToken: tokens?.accessToken || '',
        refreshToken: tokens?.refreshToken || '',
        idToken: tokens?.idToken || '',
    }
}

export const setOptions = (options: CodeFlowOptions): void => {
    getStorage().setItem('gc2_options', JSON.stringify({
                'clientId': options.clientId,
                'host': options.host,
                'redirectUri': options.redirectUri,
                'clientSecret': options.clientSecret || null,
            }
        )
    )
}

export const getOptions = (): CodeFlowOptions => {
    const str: string | null = getStorage().getItem('gc2_options')
    const options: any = str ? JSON.parse(str) : {}
    return {
        clientId: options?.clientId || '',
        host: options?.host || '',
        redirectUri: options?.redirectUri || '',
    }
}

export const base64UrlEncodeString = (str: string): string => {
    return btoa(new TextEncoder().encode(str).reduce((acc, byte) => acc + String.fromCharCode(byte), ''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

export const clearTokens = (): void => {
    getStorage().removeItem('gc2_tokens')
}

export const clearOptions = (): void => {
    getStorage().removeItem('gc2_options')
}

export const getNonce = (): string|null => {
    return <string>getStorage().getItem('gc2_nonce')
}
export const clearNonce = (): void => {
    getStorage().removeItem('gc2_nonce')
}

