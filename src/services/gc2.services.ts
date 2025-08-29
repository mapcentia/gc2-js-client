import {CodeFlowOptions, GetTokenResponse, GetDeviceCodeResponse, getNonce} from '../util/utils';

export class Gc2Service {
    private readonly options: CodeFlowOptions;
    private readonly host: string;

    constructor(options: CodeFlowOptions) {
        this.options = options;
        this.host = options.host;
    }

    private buildUrl(path: string): string {
        if (path.startsWith('http://') || path.startsWith('https://')) {
            return path;
        }
        return `${this.host}${path}`;
    }

    private async request(
        url: string,
        method: 'GET' | 'POST',
        body?: any,
        contentType: 'application/json' | 'application/x-www-form-urlencoded' = 'application/json'
    ): Promise<any> {
        const headers: Record<string, string> = {'Content-Type': contentType};
        let payload: string;

        if (contentType === 'application/json') {
            payload = JSON.stringify(body);
        } else {
            payload = new URLSearchParams(body).toString();
        }

        const response = await fetch(url, {
            method,
            headers,
            body: payload,
        });

        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`HTTP error ${response.status}: ${errText}`);
        }

        return response.json();
    }

    async getDeviceCode(): Promise<GetDeviceCodeResponse> {
        const path = this.options.deviceUri ?? '/api/v4/oauth/device';
        return this.request(this.buildUrl(path), 'POST', {
            client_id: this.options.clientId,
        });
    }

    async pollToken(deviceCode: string, interval: number): Promise<GetTokenResponse> {
        const path = this.options.tokenUri ?? '/api/v4/oauth';
        const getToken = async (): Promise<GetTokenResponse | null | string> => {
            try {
                return await this.request(
                    this.buildUrl(path),
                    'POST',
                    {
                        client_id: this.options.clientId,
                        device_code: deviceCode,
                        grant_type: 'device_code',
                    }
                );
            } catch (e: any) {
                const err = JSON.parse(e.message.split(': ')[1]);
                if (err.error === 'authorization_pending') {
                    return null;
                }
                return err.error_description;
            }
        };

        let response = await getToken();
        while (response === null) {
            await new Promise(resolve => setTimeout(resolve, interval * 1100));
            response = await getToken();
        }

        if (typeof response === 'string') {
            throw new Error(response);
        }

        return response;
    }

    getAuthorizationCodeURL(codeChallenge: string, state: string): string {
        const base = this.options.authUri ?? `${this.host}/auth/`;
        const params = new URLSearchParams()
        // Get nonce from local storage if it exists
        const nonce = getNonce()
        // Add parameters conditionally
        params.set('response_type', 'code');
        params.set('client_id', this.options.clientId);
        params.set('redirect_uri', this.options.redirectUri);
        params.set('state', state);
        params.set('code_challenge', codeChallenge);
        params.set('code_challenge_method', 'S256');
        if (nonce) {
            params.set('nonce', nonce);
        }
        // Only add scope if it's defined
        if (this.options.scope) {
            params.set('scope', this.options.scope);
        }
        return `${base}?${params.toString()}`;
    }

    async getAuthorizationCodeToken(
        code: string | string[],
        codeVerifier: string | null
    ): Promise<GetTokenResponse> {
        const path = this.options.tokenUri ?? '/api/v4/oauth';
        return this.request(
            this.buildUrl(path),
            'POST',
            {
                client_id: this.options.clientId,
                redirect_uri: this.options.redirectUri,
                grant_type: 'authorization_code',
                code,
                code_verifier: codeVerifier,
            },
            'application/x-www-form-urlencoded'
        );
    }

    async getPasswordToken(
        username: string,
        password: string,
        database: string
    ): Promise<GetTokenResponse> {
        const path = '/api/v3/oauth/token';
        return this.request(
            this.buildUrl(path),
            'POST',
            {
                client_id: this.options.clientId,
                grant_type: 'password',
                username,
                password,
                database,
            }
        );
    }

    async getRefreshToken(token: string): Promise<GetTokenResponse> {
        const path = this.options.tokenUri ?? '/api/v4/oauth';
        return this.request(
            this.buildUrl(path),
            'POST',
            {
                client_id: this.options.clientId,
                grant_type: 'refresh_token',
                refresh_token: token,
            }
        );
    }

    getSignOutURL(): string {
        const base = `${this.host}/signout/`;
        const params = new URLSearchParams({
            redirect_url: this.options.redirectUri,
        });
        return `${base}?${params.toString()}`;
    }
}
