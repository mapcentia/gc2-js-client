import {jwtDecode} from 'jwt-decode'
import {Gc2Service} from "../services/gc2.services";

export type Tokens = {
    accessToken: string;
    refreshToken: string;
};

export type Options = {
    host: string;
}

export type CodeFlowOptions = Options & {
    redirectUri: string;
    clientId: string;
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
    const accessToken = localStorage.getItem('accessToken')
    const refreshToken = localStorage.getItem('refreshToken')
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
                setTokens({accessToken: data.access_token, refreshToken})
                console.log('Access token refreshed')
            } catch (e) {
                throw new Error('Could not get refresh token.')
            }
        }
    }
    return true
}

export const setTokens = (tokens: Tokens) => {
    localStorage.setItem('accessToken', tokens.accessToken)
    localStorage.setItem('refreshToken', tokens.refreshToken)
}

export const setOptions = (options: CodeFlowOptions) => {
    if (options.clientId) localStorage.setItem('clientId', options.clientId)
    if (options.host) localStorage.setItem('host', options.host)
    if (options.redirectUri) localStorage.setItem('redirectUri', options.redirectUri)
}

export const getTokens = (): Tokens => {
    return {
        accessToken: localStorage.getItem('accessToken') || '',
        refreshToken: localStorage.getItem('refreshToken') || '',
    }
}
export const getOptions = (): CodeFlowOptions => {
    return {
        clientId: localStorage.getItem('clientId') || '',
        host: localStorage.getItem('host') || '',
        redirectUri: localStorage.getItem('redirectUri') || '',
    }
}

export const base64UrlEncodeString = (str: string): string => {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const clearTokens = (): void => {
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
}

export const clearOptions = (): void => {
    localStorage.removeItem('clientId')
    localStorage.removeItem('host')
    localStorage.removeItem('redirectUri')
}


