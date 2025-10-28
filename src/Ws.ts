import {WsOptions, getTokens} from "./util/utils";

export default class Ws {
    private readonly options: WsOptions;

    constructor(options: WsOptions) {
        this.options = options;
        this.options.wsClient = this.options?.wsClient ?? WebSocket
    }

    connect(): void {
        const me = this;
        const {accessToken} = getTokens()

        const connect = () => {
            let queryString = `?token=` + accessToken
            if (this.options?.rel) {
                queryString = queryString + `&rel=` + this.options.rel
            }
            const WSClass = this.options.wsClient as any;
            const ws: WebSocket = new WSClass(
                this.options.host + `/` + queryString,
            );

            ws.onopen = function () {
                console.log('WebSocket connected!');
            };

            ws.onmessage = function (event: MessageEvent) {
                // Handle incoming messages
                me.options.callBack((event as any).data)
            };

            ws.onclose = function (event: CloseEvent) {
                if (accessToken !== '') {
                    console.log('WebSocket closed, reconnecting in 3 seconds...', (event as any).reason);
                    setTimeout(connect, 3000); // Try to reconnect
                }
            };

            ws.onerror = function (err: Event) {
                console.error('WebSocket error observed:', err);
                // Close the socket on error to ensure clean reconnection
                ws.close();
            };
        };

        // Start the connection
        if (accessToken !== '') {
            connect();
        }
    }
}
