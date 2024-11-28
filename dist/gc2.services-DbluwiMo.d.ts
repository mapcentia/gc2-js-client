import { AxiosInstance } from 'axios';

type Tokens = {
    accessToken: string;
    refreshToken: string;
};
type Options = {
    redirectUri: string;
    clientId: string;
    host: string;
};
declare const generatePkceChallenge: () => Promise<{
    state: string;
    codeVerifier: string;
    codeChallenge: string;
}>;
declare const isTokenExpired: (token: string) => boolean;
declare const passwordIsStrongEnough: (password: string, allowNull?: boolean) => true | "Entered password is too weak";
declare const isLogin: (gc2: Gc2Service) => Promise<boolean>;
declare const setTokens: (tokens: Tokens) => void;
declare const setOptions: (options: Options) => void;
declare const getTokens: () => Tokens;
declare const getOptions: () => Options;

type GetDeviceCodeResponse = {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete?: string;
    expires_in: number;
    interval: number;
};
type GetTokenResponse = {
    access_token: string;
    expires_in: number;
    refresh_expires_in: number;
    refresh_token: string;
    token_type: string;
    'not-before-policy': number;
    session_state: string;
    scope: string;
};
declare class Gc2Service {
    http: AxiosInstance;
    options: Options;
    constructor(options: Options);
    getDeviceCode(): Promise<GetDeviceCodeResponse>;
    poolToken(deviceCode: string, interval: number): Promise<GetTokenResponse>;
    getAuthorizationCodeURL(codeChallenge: string, state: string): string;
    getAuthorizationCodeToken(code: string | string[], codeVerifier: string | null): Promise<GetTokenResponse>;
    getPasswordToken(username: string, password: string, database: string): Promise<GetTokenResponse>;
    getRefreshToken(token: string): Promise<GetTokenResponse>;
    clearTokens(): void;
    clearOptions(): void;
}

export { Gc2Service as G, type Options as O, type Tokens as T, isLogin as a, setOptions as b, getTokens as c, getOptions as d, generatePkceChallenge as g, isTokenExpired as i, passwordIsStrongEnough as p, setTokens as s };
