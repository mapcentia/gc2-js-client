import axios, {AxiosError, AxiosInstance, AxiosRequestConfig} from 'axios'
import * as querystring from 'querystring'
import {Options} from "../util/utils";


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

export class Gc2Service {
    http: AxiosInstance
    options: Options

    constructor(options: Options) {
        this.options = options
        this.http = axios.create({
            baseURL: this.options.host
        })
    }

    async getDeviceCode(): Promise<GetDeviceCodeResponse> {
        const {data} = await this.http.post(
            `/api/v4/oauth/device`,
            {
                client_id: this.options.clientId,
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                },
            },
        )
        return data
    }

    async poolToken(deviceCode: string, interval: number): Promise<GetTokenResponse> {
        const getToken = () =>
            this.http
                .post(
                    '/api/v4/oauth',
                    {
                        client_id: this.options.clientId,
                        device_code: deviceCode,
                        grant_type: 'device_code',
                    },
                    {
                        headers: {
                            'Content-Type': 'application/json',
                        },
                    },
                )
                .then(({data}) => data)
                .catch(error => {
                    if (error instanceof AxiosError) {
                        const err = error.response?.data
                        if (err.error === 'authorization_pending') {
                            return null
                        } else {
                            return err.error_description
                        }
                    }
                })

        let response = await getToken()

        while (response === null) {
            response = await new Promise(resolve => {
                setTimeout(async () => {
                    resolve(await getToken())
                }, interval * 1100) // interval equal to 1 is equivalent to 1.1 seconds between one request and another
            })
        }


        return response
    }

    getAuthorizationCodeURL(codeChallenge: string, state: string): string {
        const queryParams = querystring.stringify({
            response_type: 'code',
            client_id: this.options.clientId,
            redirect_uri: this.options.redirectUri,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        })
        return `${this.options.host}/auth/?${queryParams}`
    }

    async getAuthorizationCodeToken(code: string | string[], codeVerifier: string | null): Promise<GetTokenResponse> {
        return this.http
            .post(
                `/api/v4/oauth`,
                {
                    client_id: this.options.clientId,
                    redirect_uri: this.options.redirectUri,
                    grant_type: 'authorization_code',
                    code,
                    code_verifier: codeVerifier,
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                },
            )
            .then(({data}) => data).catch(err => {
                throw new Error(err.message)
            })
    }

    // TODO use v4 when all has updated GC2
    async getPasswordToken(username: string, password: string, database: string): Promise<GetTokenResponse> {
        return this.http
            .post(
                `/api/v3/oauth/token`,
                {
                    client_id: this.options.clientId,
                    grant_type: 'password',
                    username,
                    password,
                    database,
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                },
            )
            .then(({data}) => data)
    }

    async getRefreshToken(token: string): Promise<GetTokenResponse> {
        return this.http
            .post(
                `/api/v4/oauth`,
                {
                    client_id: this.options.clientId,
                    grant_type: 'refresh_token',
                    refresh_token: token
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                },
            ).then(({data}) => data).catch(err => {
            })
    }

    clearTokens(): void {
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
    }
    clearOptions(): void {
        localStorage.removeItem('clientId')
        localStorage.removeItem('host')
        localStorage.removeItem('redirectUri')
    }
}
