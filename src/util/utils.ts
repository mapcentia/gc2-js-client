import {jwtDecode} from 'jwt-decode'
import {Gc2Service} from "../services/gc2.services";

export type Tokens = {
    accessToken: string;
    refreshToken: string;
    idToken?: string;
};

export type Options = {
    host: string;
    wsHost?: string;
    tokenUri?: string;
    authUri?: string;
    logoutUri?: string;
    deviceUri?: string;
    scope?: string;
}

export type CodeFlowOptions = Options & {
    redirectUri: string;
    clientId: string;
}

export type WsOptions = {
    host: string;
    callBack?: any;
}

export type GetDeviceCodeResponse = {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete?: string;
    expires_in: number;
    interval: number;
};

export type GetTokenResponse = {
    access_token: string;
    expires_in: number;
    refresh_expires_in: number;
    refresh_token: string;
    id_token?: string;
    token_type: string;
    'not-before-policy': number;
    session_state: string;
    scope: string;
};


export const generatePkceChallenge = async () => {

    const generateRandomString = () => {
        const array = new Uint32Array(28);
        crypto.getRandomValues(array);
        return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
    }

    const sha256 = (plain: string | undefined) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(plain);
        return crypto.subtle.digest('SHA-256', data);
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
    localStorage.setItem('gc2_tokens', JSON.stringify({
                'accessToken': tokens.accessToken,
                'refreshToken': tokens.refreshToken,
                'idToken': tokens?.idToken || ''
            }
        )
    )
}

export const getTokens = (): Tokens => {
    const str: string | null = localStorage.getItem('gc2_tokens')
    const tokens: any = str ? JSON.parse(str) : {}
    return {
        accessToken: tokens?.accessToken || '',
        refreshToken: tokens?.refreshToken || '',
        idToken: tokens?.idToken || '',
    }
}

export const setOptions = (options: CodeFlowOptions): void => {
    localStorage.setItem('gc2_options', JSON.stringify({
                'clientId': options.clientId,
                'host': options.host,
                'redirectUri': options.redirectUri
            }
        )
    )
}

export const getOptions = (): CodeFlowOptions => {
    const str: string | null = localStorage.getItem('gc2_options')
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
    localStorage.removeItem('gc2_tokens')
}

export const clearOptions = (): void => {
    localStorage.removeItem('gc2_options')
}

export const getNonce = (): string|null => {
    return <string>localStorage.getItem('gc2_nonce')
}
export const clearNonce = (): void => {
    localStorage.removeItem('gc2_nonce')
}

