import {WsOptions, getTokens} from "./util/utils";

export default class Ws {
    private readonly options: WsOptions;

    constructor(options: WsOptions) {
        this.options = options;
    }

    connect(): void {
        const me = this;
        const {accessToken} = getTokens()

        const connect = () => {
            const ws = new WebSocket(
                this.options.host + `/?token=` + accessToken,
            );
            ws.onopen = function() {
                console.log('WebSocket connected!');
            };

            ws.onmessage = function(event) {
                // Handle incoming messages
                me.options?.callBack(event.data)
            };

            ws.onclose = function(event) {
                if (accessToken !== '') {
                    console.log('WebSocket closed, reconnecting in 3 seconds...', event.reason);
                    setTimeout(connect, 3000); // Try to reconnect
                }
            };

            ws.onerror = function(err) {
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
