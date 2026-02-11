/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

// ------------------------------
// JSON
// ------------------------------
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;
export interface JsonObject { [key: string]: JsonValue }
export type JsonArray = JsonValue[];

// ------------------------------
// Numeric
// ------------------------------
// PostgreSQL decimal/numeric are returned as exact strings
export type DecimalString = string;
export type NumericString = string;

// ------------------------------
// Character
// ------------------------------
export type Varchar = string;
export type Char = string; // fixed length, server pads with spaces
export type BPChar = string; // synonym for char in examples
export type Text = string;

// ------------------------------
// Boolean
// ------------------------------
export type PgBoolean = boolean;

// ------------------------------
// Date/Time
// ------------------------------
export type DateString = string;       // e.g. "2011 04 01" with provided format
export type TimeString = string;       // e.g. "12:00"
export type TimetzString = string;     // e.g. "14:00:00 GMT+0200"
export type TimestampString = string;  // e.g. "Friday 3rd 2011 at 14:00:00"
export type TimestamptzString = string;// e.g. "2011-04-01T12:00:00+00:00"

export interface IntervalValue {
    y: number; // years
    m: number; // months
    d: number; // days
    h: number; // hours
    i: number; // minutes
    s: number; // seconds
}

// ------------------------------
// Geometric
// ------------------------------
export interface Point { x: number; y: number }
export interface Line { A: number; B: number; C: number }
export interface Lseg { start: Point; end: Point }
export interface Box { start: Point; end: Point }
export type Path = [isClosed: boolean, ...points: Point[]];
export type Polygon = Point[];
export interface Circle { center: Point; radius: number }

// ------------------------------
// Range
// ------------------------------
export interface Range<T> {
    lower: T;
    upper: T;
    lowerInclusive: boolean;
    upperInclusive: boolean;
}

export type Int4Range = Range<number>;
export type Int8Range = Range<number>; // Note: may exceed JS safe integer; string could be used if needed
export type NumRange = Range<NumericString>;
export type TsRange = Range<TimestampString>;
export type TstzRange = Range<TimestamptzString>;
export type DateRange = Range<DateString>;

// ------------------------------
// Arrays
// ------------------------------
export type PgArray<T> = T[];

// ------------------------------
// SQL/RPC API request/response
// ------------------------------
export interface SqlRequest<Params extends Record<string, unknown> = Record<string, unknown>> {
    q: string;
    params?: Params;
    type_hints?: Record<string, string>;   // e.g. { my_tsrange: "tsrange[]" }
    type_formats?: Record<string, string>; // e.g. { my_timestamp: "l jS Y \\a\\t H:i:s" }
}

export interface SqlResponse<Row extends DataRow = DataRow> {
    schema: Record<string, ColumnSchemaMeta>;
    data: Row[];
}

// Phantom-typed request that carries the expected row type at compile time only
export interface TypedSqlRequest<Row extends DataRow, Params extends Record<string, unknown> = Record<string, unknown>> extends SqlRequest<Params> {
    // This property is never set at runtime; it exists only to carry the Row type
    readonly __row?: Row;
}

export interface RpcRequest<Params extends Record<string, unknown> = Record<string, unknown>> {
    jsonrpc: "2.0"
    method: string
    params?: Params
    id?: number|string
}

export interface GqlRequest {
    query: string
    variables?: Record<string, unknown>
    operationName?: string
    extensions?: Record<string, unknown>
}

export interface GqlResponse {
    data?: Record<string, unknown>
    errors?: Array<{ message: string }>
}

export interface ColumnSchemaMeta {
    type: string; // Postgres type name (e.g., int2, int4, int8, numeric, jsonb, tsrange, etc.)
    array: boolean;
}

export type RowValue =
    | number
    | string
    | PgBoolean
    | JsonValue
    | DateString
    | TimeString
    | TimetzString
    | TimestampString
    | TimestamptzString
    | IntervalValue
    | Point
    | Line
    | Lseg
    | Box
    | Path
    | Polygon
    | Circle
    | Int4Range
    | Int8Range
    | NumRange
    | TsRange
    | TstzRange
    | DateRange
    | PgArray<any> // array of any of the above
    | null;

export type DataRow = Record<string, RowValue>;

export interface RpcResponse<Row extends DataRow = DataRow> {
    jsonrpc: "2.0"
    result: {
        schema: Record<string, ColumnSchemaMeta>
        data: Row[]
    }
    id: number|string
}
