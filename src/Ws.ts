/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import {getTokens} from "./util/utils";

// ── Message types ──────────────────────────────────────────────

export type BatchMessage = {
    type: 'batch';
    db: string;
    batch: Record<string, Record<string, TableBatch>>;
}

export type TableBatch = {
    INSERT?: any[][];
    UPDATE?: any[][];
    DELETE?: any[][];
    full_data?: Record<string, any>[];
}

export type SubscriptionAckMessage = {
    type: 'subscription_ack';
    id: string;
}

export type WsErrorMessage = {
    type: 'error';
    error: 'missing_token' | 'invalid_token' | 'not_allowed' | string;
    message: string;
}

export type WsMessage = BatchMessage | SubscriptionAckMessage | WsErrorMessage;

// ── Subscription ───────────────────────────────────────────────

export type SubscriptionRequest = {
    id: string;
    schema: string;
    rel: string;
    where?: string;
    columns?: string;
    op?: 'INSERT' | 'UPDATE' | 'DELETE';
}

// ── Events ─────────────────────────────────────────────────────

type WsEventMap = {
    batch: BatchMessage;
    subscription_ack: SubscriptionAckMessage;
    error: WsErrorMessage;
    open: void;
    close: { code: number; reason: string };
}

type WsEventListener<T> = (data: T) => void;

// ── Options ────────────────────────────────────────────────────

export type WsOptions = {
    host: string;
    rels?: string;
    wsClient?: unknown;
    reconnect?: boolean;
    reconnectInterval?: number;
}

// ── Class ──────────────────────────────────────────────────────

export default class Ws {
    private readonly options: WsOptions;
    private ws: WebSocket | null = null;
    private listeners: { [K in keyof WsEventMap]?: WsEventListener<WsEventMap[K]>[] } = {};
    private closed = false;

    constructor(options: WsOptions) {
        this.options = {
            reconnect: true,
            reconnectInterval: 3000,
            ...options,
        };
        this.options.wsClient = this.options.wsClient ?? WebSocket;
    }

    connect(): void {
        this.closed = false;
        this.doConnect();
    }

    disconnect(): void {
        this.closed = true;
        this.ws?.close();
        this.ws = null;
    }

    subscribe(sub: SubscriptionRequest): void {
        this.send({type: 'subscription', ...sub});
    }

    send(data: unknown): void {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error('WebSocket is not connected');
        }
        this.ws.send(typeof data === 'string' ? data : JSON.stringify(data));
    }

    on<K extends keyof WsEventMap>(event: K, listener: WsEventListener<WsEventMap[K]>): () => void {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        (this.listeners[event] as WsEventListener<WsEventMap[K]>[]).push(listener);
        return () => this.off(event, listener);
    }

    off<K extends keyof WsEventMap>(event: K, listener: WsEventListener<WsEventMap[K]>): void {
        const arr = this.listeners[event] as WsEventListener<WsEventMap[K]>[] | undefined;
        if (!arr) return;
        const idx = arr.indexOf(listener);
        if (idx !== -1) arr.splice(idx, 1);
    }

    get connected(): boolean {
        return this.ws?.readyState === WebSocket.OPEN;
    }

    // ── Private ────────────────────────────────────────────────

    private emit<K extends keyof WsEventMap>(event: K, data: WsEventMap[K]): void {
        const arr = this.listeners[event] as WsEventListener<WsEventMap[K]>[] | undefined;
        if (!arr) return;
        for (const fn of arr) fn(data);
    }

    private doConnect(): void {
        const {accessToken} = getTokens();
        if (!accessToken) return;

        let url = this.options.host + '/?token=' + encodeURIComponent(accessToken);
        if (this.options.rels) {
            url += '&rels=' + encodeURIComponent(this.options.rels);
        }

        const WSClass = this.options.wsClient as any;
        const ws: WebSocket = new WSClass(url);
        this.ws = ws;

        ws.onopen = () => {
            this.emit('open', undefined as any);
        };

        ws.onmessage = (event: MessageEvent) => {
            let msg: WsMessage;
            try {
                msg = JSON.parse(typeof event.data === 'string' ? event.data : event.data.toString());
            } catch {
                return;
            }
            switch (msg.type) {
                case 'batch':
                    this.emit('batch', msg);
                    break;
                case 'subscription_ack':
                    this.emit('subscription_ack', msg);
                    break;
                case 'error':
                    this.emit('error', msg);
                    break;
            }
        };

        ws.onclose = (event: CloseEvent) => {
            this.emit('close', {code: event.code, reason: event.reason});
            if (!this.closed && this.options.reconnect) {
                setTimeout(() => this.doConnect(), this.options.reconnectInterval);
            }
        };

        ws.onerror = () => {
            ws.close();
        };
    }
}
