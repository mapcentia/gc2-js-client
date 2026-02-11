/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { SqlRequest } from "./types/pgTypes";
import * as PgTypes from "./types/pgTypes";

// Basic schema types (matches provided schema/schema.json shape)
export interface ColumnDef {
  name: string;
  _typname: string; // e.g. int4, varchar, jsonb
  _is_array: boolean;
  is_nullable: boolean;
  type?: string; // e.g. character varying(255)
  [key: string]: any;
}

export interface ConstraintDef {
  name: string;
  constraint: "primary" | "foreign" | string;
  columns?: readonly string[];
  referenced_table?: string;
  referenced_columns?: readonly string[];
  check?: string;
}

export interface TableDef {
  name: string;
  // Use readonly arrays so `as const` schemas preserve literal column names for typing
  columns: readonly ColumnDef[];
  constraints?: readonly ConstraintDef[];
  [key: string]: any;
}

export interface DBSchema {
  name: string;
  // Use readonly arrays so `as const` schemas preserve literal table names for typing
  tables: readonly TableDef[];
}

export type ScalarFromTypename<T extends string> =
// Numeric
    T extends "int2" | "int4" | "int8" ? number :
        T extends "float4" | "float8" ? number :
            T extends "numeric" | "decimal" ? PgTypes.NumericString :
                // Character
                T extends "varchar" | "text" | "bpchar" | "char" ? string :
                    // Boolean
                    T extends "bool" ? PgTypes.PgBoolean :
                        // JSON
                        T extends "json" | "jsonb" ? PgTypes.JsonValue :
                            // Date/Time
                            T extends "date" ? PgTypes.DateString :
                                T extends "time" ? PgTypes.TimeString :
                                    T extends "timetz" ? PgTypes.TimetzString :
                                        T extends "timestamp" ? PgTypes.TimestampString :
                                            T extends "timestamptz" ? PgTypes.TimestamptzString :
                                                T extends "interval" ? PgTypes.IntervalValue :
                                                    // Geometric
                                                    T extends "point" ? PgTypes.Point :
                                                        T extends "line" ? PgTypes.Line :
                                                            T extends "lseg" ? PgTypes.Lseg :
                                                                T extends "box" ? PgTypes.Box :
                                                                    T extends "path" ? PgTypes.Path :
                                                                        T extends "polygon" ? PgTypes.Polygon :
                                                                            T extends "circle" ? PgTypes.Circle :
                                                                                // Ranges
                                                                                T extends "int4range" ? PgTypes.Int4Range :
                                                                                    T extends "int8range" ? PgTypes.Int8Range :
                                                                                        T extends "numrange" ? PgTypes.NumRange :
                                                                                            T extends "tsrange" ? PgTypes.TsRange :
                                                                                                T extends "tstzrange" ? PgTypes.TstzRange :
                                                                                                    T extends "daterange" ? PgTypes.DateRange :
                                                                                                        string;

// If schema object is declared with `as const`, these produce better types.
export type TableNames<S extends DBSchema> = S["tables"][number]["name"];
export type TableByName<S extends DBSchema, TN extends string> = Extract<S["tables"][number], { name: TN }>;
export type ColumnsOf<S extends DBSchema, TN extends string> = TableByName<S, TN>["columns"];
export type ColumnNames<S extends DBSchema, TN extends string> = ColumnsOf<S, TN>[number]["name"];

// Constraint helpers for typing allowed JOIN targets
type ConstraintsOfTable<T extends TableDef> = T["constraints"] extends readonly any[] ? T["constraints"][number] : never;

type ReferencedTablesOfTable<T extends TableDef> = ConstraintsOfTable<T> extends infer C
    ? C extends { constraint: "foreign"; referenced_table: infer RT extends string }
        ? RT
        : never
    : never;

// Allowed join targets when selecting from TN: only tables referenced by TN via foreign key constraints
export type AllowedJoinTables<S extends DBSchema, TN extends string> = ReferencedTablesOfTable<TableByName<S, TN>>;

// Primary key helpers for typing wherePk
// Extract the primary constraint for a table (if any)
type PrimaryConstraintOfTable<T extends TableDef> = ConstraintsOfTable<T> extends infer C
    ? Extract<C, { constraint: "primary" }>
    : never;

// The list of PK column names for the table (as a readonly tuple when schema is const)
type PrimaryKeyColumns<S extends DBSchema, TN extends string> = PrimaryConstraintOfTable<TableByName<S, TN>> extends {
    columns: infer A extends readonly string[]
}
    ? A
    : never;

type IsTupleOfLength1<T extends readonly any[]> = T extends readonly [any] ? true : false;

// Value type accepted by wherePk():
// - single-column PK -> that column's value type
// - composite PK -> an object with all PK columns
// - no PK -> never (method becomes impossible to call in TS)
export type PrimaryKeyValue<S extends DBSchema, TN extends string> = PrimaryKeyColumns<S, TN> extends infer PK extends readonly string[]
    ? PK extends never
        ? never
        : IsTupleOfLength1<PK> extends true
            ? ColumnValueFor<S, TN, PK[0]>
            : { [K in PK[number]]: ColumnValueFor<S, TN, K> }
    : never;

// Value type for a column based on typname and array/nullability flags.
// Note: If schema is not `as const`, flags are not literal and result type becomes broader.
export type ColumnValueFromDef<C extends ColumnDef> =
  C["_is_array"] extends true
    ? PgTypes.PgArray<ScalarFromTypename<C["_typname"]>>
    : ScalarFromTypename<C["_typname"]>;

export type NullableColumnValueFromDef<C extends ColumnDef> =
  C["is_nullable"] extends true ? ColumnValueFromDef<C> | null : ColumnValueFromDef<C>;

// Helpers to map a column name to its definition and value type
export type ColumnDefByName<S extends DBSchema, TN extends string, K extends string> = Extract<ColumnsOf<S, TN>[number], { name: K }>;
export type ColumnValueFor<S extends DBSchema, TN extends string, K extends string> = NullableColumnValueFromDef<ColumnDefByName<S, TN, K>>;

export type ValuesForTable<S extends DBSchema, TN extends string> = Partial<{
  [K in ColumnNames<S, TN>]: NullableColumnValueFromDef<Extract<ColumnsOf<S, TN>[number], { name: K }>>
}>;

// Where clause accepts equality and array (= ANY()) semantics.
export type WhereForTable<S extends DBSchema, TN extends string> = Partial<{
  [K in ColumnNames<S, TN>]:
    | NullableColumnValueFromDef<Extract<ColumnsOf<S, TN>[number], { name: K }>>
    | NullableColumnValueFromDef<Extract<ColumnsOf<S, TN>[number], { name: K }>>[]
}>;

// Extended operator support for where-chaining
export type WhereOperator =
  | "="
  | "!="
  | "<"
  | "<="
  | ">"
  | ">="
  | "like"
  | "ilike"
  | "notlike"
  | "notilike"
  | "in"
  | "notin"
  | "isnull"
  | "notnull";

// Typed operator predicate for group APIs (compile-time value checks per operator)
export type OpPredicateForCol<S extends DBSchema, TN extends string, K extends ColumnNames<S, TN>> =
  | readonly [K, "isnull" | "notnull"]
  | readonly [K, "like" | "ilike" | "notlike" | "notilike", string]
  | readonly [K, "in" | "notin", ReadonlyArray<ColumnValueFor<S, TN, K>>]
  | readonly [K, "=" | "!=" | "<" | "<=" | ">" | ">=", ColumnValueFor<S, TN, K>];

export type OpPredicate<S extends DBSchema, TN extends string> = {
  [K in ColumnNames<S, TN>]: OpPredicateForCol<S, TN, K>
}[ColumnNames<S, TN>];

// Additional type helpers
export type IsAny<T> = 0 extends (1 & T) ? true : false;

export type OpArgsFor<S extends DBSchema, TN extends string, K extends ColumnNames<S, TN>, O extends WhereOperator> =
  IsAny<O> extends true ? never[] :
  O extends "isnull" | "notnull" ? [] :
  O extends "like" | "ilike" | "notlike" | "notilike" ? [value: string] :
  O extends "in" | "notin" ? [value: ReadonlyArray<ColumnValueFor<S, TN, K>>] :
  O extends "=" | "!=" | "<" | "<=" | ">" | ">=" ? [value: ColumnValueFor<S, TN, K>] :
  never[];

// ---------- Runtime helpers ----------
function findTable(schema: DBSchema, name: string): TableDef {
  const tbl = schema.tables.find(t => t.name === name);
  if (!tbl) throw new Error(`Table not found in schema: ${name}`);
  return tbl;
}

function findColumn(table: TableDef, name: string): ColumnDef {
    const col = table.columns.find(c => c.name === name);
    if (!col) throw new Error(`Column not found in table ${table.name}: ${name}`);
    return col;
}

function getPrimaryKeyColumns(table: TableDef): string[] {
    const cs = table.constraints || [];
    const pk = cs.find(c => c.constraint === "primary" && Array.isArray(c.columns) && c.columns.length > 0);
    return pk ? (pk.columns as readonly string[]).map(String) : [];
}

function typeNameToHint(typname: string, isArray: boolean): string | undefined {
  if (!typname) return undefined;
  const base = typname; // Already pg typname
  return isArray ? base + "[]" : base;
}

// Utility to push type_hints for array params, since arrays are not inferred by default.
function addTypeHintForParam(
  typeHints: Record<string, string>,
  paramName: string,
  col: ColumnDef,
  value: unknown
) {
  // Always provide a type hint: scalar as base typname, arrays as base[]
  // Special-case array-shaped geometric scalars (path, polygon):
  // - Equality scalar: value looks like an array but represents a single scalar -> hint as base (no [])
  // - IN/ANY arrays: value is array of those scalars (nested arrays) -> hint as base[]
  let isArr = col._is_array;
  if (Array.isArray(value)) {
    if (isArrayShapedGeomTypename(col._typname)) {
      const top = value as unknown[];
      // If every element is itself an array, it's an array of geom scalars
      isArr = top.every(Array.isArray);
    } else {
      isArr = true;
    }
  }
  const hint = typeNameToHint(col._typname, isArr);
  if (hint) typeHints[paramName] = hint;
}

// Runtime value type validation helpers for whereOp predicates
function expectedScalarKind(typname: string): "number" | "string" | "boolean" | "json" | "range" | "interval" | "geom" | "unknown" {
  const t = typname.toLowerCase();
  if (t === "int2" || t === "int4" || t === "int8" || t === "float4" || t === "float8") return "number";
  if (t === "numeric" || t === "decimal") return "string"; // numeric represented as string in SDK
  if (t === "varchar" || t === "text" || t === "bpchar" || t === "char" || t === "date" || t === "time" || t === "timetz" || t === "timestamp" || t === "timestamptz") return "string";
  if (t === "bool") return "boolean";
  if (t === "json" || t === "jsonb") return "json";
  if (t === "int4range" || t === "int8range" || t === "numrange" || t === "tsrange" || t === "tstzrange" || t === "daterange") return "range";
  if (t === "interval") return "interval";
  if (t === "point" || t === "line" || t === "lseg" || t === "box" || t === "path" || t === "polygon" || t === "circle") return "geom";
  return "unknown";
}

function isArrayShapedGeomTypename(typname: string): boolean {
  const t = typname.toLowerCase();
  // path and polygon are represented as arrays at the value level, but are scalar types in PG
  return t === "path" || t === "polygon";
}

function isArrayShapedGeomScalarValue(col: ColumnDef, value: unknown): boolean {
  // Detect if a provided array value represents a single scalar for array-shaped geometric types
  if (!Array.isArray(value)) return false;
  if (!isArrayShapedGeomTypename(col._typname)) return false;
  const top = value as unknown[];
  // If every element is an array, then this is an array of scalars (for IN/ANY)
  // Otherwise, it's a single scalar (path or polygon)
  return !top.every(Array.isArray);
}

function expectedRangeInnerKind(typname: string): "number" | "string" | "unknown" {
  const t = typname.toLowerCase();
  if (t === "int4range" || t === "int8range") return "number";
  if (t === "numrange" || t === "tsrange" || t === "tstzrange" || t === "daterange") return "string";
  return "unknown";
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isFiniteNumber(n: unknown): n is number {
  return typeof n === "number" && Number.isFinite(n);
}

function isPointLike(v: unknown): v is { x: number; y: number } {
  if (!isPlainObject(v)) return false;
  const x = (v as any).x;
  const y = (v as any).y;
  return isFiniteNumber(x) && isFiniteNumber(y);
}

function validateGeometryForColumn(col: ColumnDef, value: unknown, context: string): void {
  const t = col._typname.toLowerCase();

  if (t === "point") {
    if (!isPointLike(value)) {
      throw new Error(`Invalid value for ${context}. Expected Point { x: number, y: number }`);
    }
    return;
  }

  if (t === "line") {
    if (!isPlainObject(value)) throw new Error(`Invalid value for ${context}. Expected Line { A: number, B: number, C: number }`);
    const A = (value as any).A, B = (value as any).B, C = (value as any).C;
    if (!isFiniteNumber(A) || !isFiniteNumber(B) || !isFiniteNumber(C)) {
      throw new Error(`Invalid Line for ${context}. A, B, C must be finite numbers`);
    }
    return;
  }

  if (t === "lseg" || t === "box") {
    if (!isPlainObject(value)) throw new Error(`Invalid value for ${context}. Expected ${t.toUpperCase()} { start: Point, end: Point }`);
    const start = (value as any).start;
    const end = (value as any).end;
    if (!isPointLike(start) || !isPointLike(end)) {
      throw new Error(`Invalid ${t} for ${context}. 'start' and 'end' must be Point { x, y }`);
    }
    return;
  }

  if (t === "path") {
    if (!Array.isArray(value) || value.length < 1) {
      throw new Error(`Invalid value for ${context}. Expected Path [isClosed: boolean, ...points: Point[]]`);
    }
    const [isClosed, ...points] = value as any[];
    if (typeof isClosed !== "boolean") {
      throw new Error(`Invalid Path for ${context}. First element must be boolean (isClosed)`);
    }
    for (let i = 0; i < points.length; i++) {
      if (!isPointLike(points[i])) {
        throw new Error(`Invalid Path for ${context}. Element at index ${i + 1} must be Point { x, y }`);
      }
    }
    return;
  }

  if (t === "polygon") {
    if (!Array.isArray(value)) {
      throw new Error(`Invalid value for ${context}. Expected Polygon as Point[]`);
    }
    for (let i = 0; i < value.length; i++) {
      if (!isPointLike((value as any)[i])) {
        throw new Error(`Invalid Polygon for ${context}. Element at index ${i} must be Point { x, y }`);
      }
    }
    return;
  }

  if (t === "circle") {
    if (!isPlainObject(value)) throw new Error(`Invalid value for ${context}. Expected Circle { center: Point, radius: number }`);
    const center = (value as any).center;
    const radius = (value as any).radius;
    if (!isPointLike(center) || !isFiniteNumber(radius)) {
      throw new Error(`Invalid Circle for ${context}. 'center' must be Point and 'radius' must be finite number`);
    }
    return;
  }

  // Unknown geometric subtype; skip
}

function validateRangeForColumn(col: ColumnDef, value: unknown, context: string): void {
  if (!isPlainObject(value)) {
    throw new Error(`Invalid value for ${context}. Expected a range object for type ${col._typname}`);
  }
  const r = value as Record<string, unknown>;
  const hasLower = Object.prototype.hasOwnProperty.call(r, "lower");
  const hasUpper = Object.prototype.hasOwnProperty.call(r, "upper");
  const hasLi = Object.prototype.hasOwnProperty.call(r, "lowerInclusive");
  const hasUi = Object.prototype.hasOwnProperty.call(r, "upperInclusive");
  if (!hasLower || !hasUpper || !hasLi || !hasUi) {
    throw new Error(`Invalid range for ${context}. Required properties: lower, upper, lowerInclusive, upperInclusive`);
  }
  if (typeof r.lowerInclusive !== "boolean" || typeof r.upperInclusive !== "boolean") {
    throw new Error(`Invalid range for ${context}. lowerInclusive and upperInclusive must be boolean`);
  }
  const inner = expectedRangeInnerKind(col._typname);
  if (inner === "number") {
    if (typeof r.lower !== "number" || !Number.isFinite(r.lower as number)) {
      throw new Error(`Invalid range.lower for ${context}. Expected number for type ${col._typname}`);
    }
    if (typeof r.upper !== "number" || !Number.isFinite(r.upper as number)) {
      throw new Error(`Invalid range.upper for ${context}. Expected number for type ${col._typname}`);
    }
  } else if (inner === "string") {
    if (typeof r.lower !== "string") {
      throw new Error(`Invalid range.lower for ${context}. Expected string for type ${col._typname}`);
    }
    if (typeof r.upper !== "string") {
      throw new Error(`Invalid range.upper for ${context}. Expected string for type ${col._typname}`);
    }
  } else {
    // Unknown inner kind; best-effort: accept as-is
  }
}

function validateIntervalForColumn(col: ColumnDef, value: unknown, context: string): void {
  if (!isPlainObject(value)) {
    throw new Error(`Invalid value for ${context}. Expected an interval object for type ${col._typname}`);
  }
  const v = value as Record<string, unknown>;
  const keys: (keyof PgTypes.IntervalValue)[] = ["y", "m", "d", "h", "i", "s"];
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(v, k)) {
      throw new Error(`Invalid interval for ${context}. Missing property '${k}'`);
    }
    const num = (v as any)[k];
    if (typeof num !== "number" || !Number.isFinite(num)) {
      throw new Error(`Invalid interval.${String(k)} for ${context}. Expected finite number`);
    }
  }
}

function isValidJsonLike(value: unknown): boolean {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    (typeof value === "object" && value !== null)
  );
}

function validateScalarForColumn(col: ColumnDef, value: unknown, context: string): void {
  const kind = expectedScalarKind(col._typname);
  if (kind === "unknown") return; // best-effort: skip strict check for unknown types
  if (kind === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new Error(`Invalid value for ${context}. Expected number for type ${col._typname}, got ${typeof value}`);
    }
    return;
  }
  if (kind === "string") {
    if (typeof value !== "string") {
      throw new Error(`Invalid value for ${context}. Expected string for type ${col._typname}, got ${typeof value}`);
    }
    return;
  }
  if (kind === "boolean") {
    if (typeof value !== "boolean") {
      throw new Error(`Invalid value for ${context}. Expected boolean for type ${col._typname}, got ${typeof value}`);
    }
    return;
  }
  if (kind === "json") {
    if (!isValidJsonLike(value)) {
      throw new Error(`Invalid value for ${context}. Expected JSON-compatible value for type ${col._typname}`);
    }
    return;
  }
  if (kind === "range") {
    validateRangeForColumn(col, value, context);
    return;
  }
  if (kind === "interval") {
    validateIntervalForColumn(col, value, context);
    return;
  }
  if (kind === "geom") {
    validateGeometryForColumn(col, value, context);
    return;
  }
}

function validateComparisonValue(col: ColumnDef, key: string, value: unknown, op: string): void {
  if (value === undefined || value === null) {
    throw new Error(`Operator ${op} on column ${key} requires a non-null value. Use isnull/notnull for null checks.`);
  }
  if (col._is_array) {
    if (!Array.isArray(value)) {
      throw new Error(`Operator ${op} on array column ${key} requires an array value`);
    }
    for (const [i, v] of (value as unknown[]).entries()) {
      validateScalarForColumn(col, v, `column ${key}[${i}]`);
    }
  } else {
    if (Array.isArray(value) && !isArrayShapedGeomScalarValue(col, value)) {
      throw new Error(`Operator ${op} on scalar column ${key} cannot accept an array value`);
    }
    // Note: some scalar types (path, polygon) appear as arrays at the value level; they are handled by validateScalarForColumn
    validateScalarForColumn(col, value, `column ${key}`);
  }
}

function validateInArrayValues(col: ColumnDef, key: string, values: unknown[], op: string): void {
  // For scalar columns ensure each element matches the scalar type. For array-typed columns, we only ensure it's an array of anything (Postgres may accept array of arrays); keep minimal.
  if (!col._is_array) {
    let idx = 0;
    for (const v of values) {
      validateScalarForColumn(col, v, `column ${key} (element ${idx})`);
      idx++;
    }
  }
}

// Attempt to derive join ON pairs between two tables using foreign key constraints.
function findJoinOn(base: TableDef, target: TableDef): { left: string; right: string }[] | null {
  const bc = base.constraints || [];
  const tc = target.constraints || [];

  // Case 1: base has FK referencing target
  for (const c of bc) {
    if (c.constraint === "foreign" && c.referenced_table === target.name && c.columns?.length && c.referenced_columns?.length && c.columns.length === c.referenced_columns.length) {
      return c.columns.map((col, i) => ({ left: String(col), right: String(c.referenced_columns![i]) }));
    }
  }
  // Case 2: target has FK referencing base
  for (const c of tc) {
    if (c.constraint === "foreign" && c.referenced_table === base.name && c.columns?.length && c.referenced_columns?.length && c.columns.length === c.referenced_columns.length) {
      return c.referenced_columns.map((rcol, i) => ({ left: String(rcol), right: String(c.columns![i]) }));
    }
  }
  return null;
}

// ---------- Builders ----------
export interface SqlBuilder<S extends DBSchema> {
  table: <TN extends TableNames<S>>(name: TN) => TableQuery<S, TN>;
}

// Row type helpers for selections
export type RowForTable<S extends DBSchema, TN extends string> = {
  [K in ColumnNames<S, TN>]: ColumnValueFor<S, TN, K>
};
export type PickRow<S extends DBSchema, TN extends string, C extends ReadonlyArray<ColumnNames<S, TN>>> = {
  [K in C[number]]: ColumnValueFor<S, TN, K>
};

// Extractor helpers: infer the row type from a SelectQuery or TypedSqlRequest
export type RowOfSelect<Q> = Q extends SelectQuery<any, any, infer R> ? R : never;
export type RowsOfSelect<Q> = RowOfSelect<Q>[];

export type RowOfRequest<Rq> = Rq extends PgTypes.TypedSqlRequest<infer R> ? R : never;
export type RowsOfRequest<Rq> = RowOfRequest<Rq>[];

export interface TableQuery<S extends DBSchema, TN extends string> {
  // SELECT
  select(): SelectQuery<S, TN, RowForTable<S, TN>>;
  select<C extends ReadonlyArray<ColumnNames<S, TN>>>(cols: C): SelectQuery<S, TN, PickRow<S, TN, C>>;
  // INSERT
  insert: (values: ValuesForTable<S, TN>) => InsertQuery<S, TN>;
  // UPDATE
  update: (values: Partial<ValuesForTable<S, TN>>) => UpdateQuery<S, TN>;
  // DELETE
  delete: () => DeleteQuery<S, TN>;
}

export interface SelectQuery<S extends DBSchema, TN extends string, R extends PgTypes.DataRow> {
  selectFrom: <JT extends TableNames<S>>(table: JT, cols?: ReadonlyArray<ColumnNames<S, JT>>) => SelectQuery<S, TN, R>;
  andWhere: (where: WhereForTable<S, TN>) => SelectQuery<S, TN, R>;
  /** @deprecated Use andWhere() instead */
  where: (where: WhereForTable<S, TN>) => SelectQuery<S, TN, R>;
  orWhere: (where: WhereForTable<S, TN>) => SelectQuery<S, TN, R>;
  wherePk: (pk: PrimaryKeyValue<S, TN>) => SelectQuery<S, TN, R>;
  // Operator-based where chaining with compile-time value checks; also rejects `any` operator by disallowing extra args when O is any
  andWhereOp<K extends ColumnNames<S, TN>, O extends WhereOperator>(col: K, op: O, ...args: OpArgsFor<S, TN, K, O>): SelectQuery<S, TN, R>;
  orWhereOp<K extends ColumnNames<S, TN>, O extends WhereOperator>(col: K, op: O, ...args: OpArgsFor<S, TN, K, O>): SelectQuery<S, TN, R>;
  andWhereOpGroup: (predicates: ReadonlyArray<OpPredicate<S, TN>>) => SelectQuery<S, TN, R>;
  orWhereOpGroup: (predicates: ReadonlyArray<OpPredicate<S, TN>>) => SelectQuery<S, TN, R>;
  orderBy: (order: ReadonlyArray<readonly [ColumnNames<S, TN>, "asc" | "desc"]> | ColumnNames<S, TN>) => SelectQuery<S, TN, R>;
  limit: (n: number) => SelectQuery<S, TN, R>;
  offset: (n: number) => SelectQuery<S, TN, R>;
  join: <JT extends TableNames<S>>(table: JT, type?: "inner" | "left" | "right" | "full") => SelectQuery<S, TN, R>;
  toSql: () => PgTypes.TypedSqlRequest<R>;
}

export interface InsertQuery<S extends DBSchema, TN extends string> {
  returning: (cols?: ReadonlyArray<ColumnNames<S, TN>>) => InsertQuery<S, TN>;
  toSql: () => SqlRequest<Record<string, unknown>>;
}

export interface UpdateQuery<S extends DBSchema, TN extends string> {
  where: (where: WhereForTable<S, TN>) => UpdateQuery<S, TN>;
  wherePk: (pk: PrimaryKeyValue<S, TN>) => UpdateQuery<S, TN>;
  returning: (cols?: ReadonlyArray<ColumnNames<S, TN>>) => UpdateQuery<S, TN>;
  toSql: () => SqlRequest<Record<string, unknown>>;
}

export interface DeleteQuery<S extends DBSchema, TN extends string> {
  where: (where: WhereForTable<S, TN>) => DeleteQuery<S, TN>;
  wherePk: (pk: PrimaryKeyValue<S, TN>) => DeleteQuery<S, TN>;
  returning: (cols?: ReadonlyArray<ColumnNames<S, TN>>) => DeleteQuery<S, TN>;
  toSql: () => SqlRequest<Record<string, unknown>>;
}

class TableQueryImpl<S extends DBSchema, TN extends string> implements TableQuery<S, TN> {
  private readonly schema: DBSchema;
  private readonly table: TableDef;

  constructor(schema: DBSchema, tableName: string) {
    this.schema = schema;
    this.table = findTable(schema, tableName);
  }

  // Overloads provide precise row typing based on selected columns
  select(): SelectQuery<S, TN, RowForTable<S, TN>>;
  select<C extends ReadonlyArray<ColumnNames<S, TN>>>(cols: C): SelectQuery<S, TN, PickRow<S, TN, C>>;
  select(cols?: ReadonlyArray<ColumnNames<S, TN>>): any {
    const table = this.table;
    const schema = this.schema;
    const selected = (cols && cols.length ? cols : ["*"]) as (ColumnNames<S, TN> | "*")[];
    const state = {
      table,
      selected,
      where: {} as WhereForTable<S, TN>,
      orWhereGroups: [] as WhereForTable<S, TN>[],
      // Operator-based predicates
      andOps: [] as { col: ColumnNames<S, TN>; op: WhereOperator; value?: unknown }[],
      orOpGroups: [] as { col: ColumnNames<S, TN>; op: WhereOperator; value?: unknown }[][],
      order: [] as { col: ColumnNames<S, TN>; dir: "asc" | "desc" }[],
      limit: undefined as number | undefined,
      offset: undefined as number | undefined,
      joins: [] as { type: "inner" | "left" | "right" | "full"; source: TableDef; target: TableDef; on: { left: string; right: string }[] }[],
      joinSelections: [] as { target: TableDef; selected: (string | "*")[] }[],
    };

    return new (class implements SelectQuery<S, TN, any> {
      private s = state;

      selectFrom<JT extends TableNames<S>>(tableName: JT, cols?: ReadonlyArray<ColumnNames<S, JT>>): SelectQuery<S, TN, any> {
        const jtName = String(tableName);
        const join = this.s.joins.find(j => j.target.name === jtName);
        if (!join) {
          throw new Error(`selectFrom('${jtName}') requires a prior join('${jtName}') call`);
        }
        const sel = (!cols || (cols as readonly any[]).length === 0) ? ["*"] : (cols as readonly any[]).map(String);
        if (!(sel.length === 1 && sel[0] === "*")) {
          for (const c of sel) findColumn(join.target, String(c));
        }
        const existing = this.s.joinSelections.find(js => js.target.name === jtName);
        if (existing) {
          if (existing.selected.includes("*")) return this;
          if (sel.length === 1 && sel[0] === "*") {
            existing.selected = ["*"];
          } else {
            const set = new Set(existing.selected as string[]);
            for (const c of sel) set.add(String(c));
            existing.selected = Array.from(set);
          }
        } else {
          this.s.joinSelections.push({ target: join.target, selected: sel as (string | "*")[] });
        }
        return this;
      }

      andWhere(where: WhereForTable<S, TN>): SelectQuery<S, TN, any> {
        // merge
        for (const k in where as Record<string, unknown>) this.s.where[k as keyof typeof where] = (where as any)[k];
        return this;
      }
      /** @deprecated Use andWhere() instead */
      where(where: WhereForTable<S, TN>): SelectQuery<S, TN, any> { return this.andWhere(where); }

      orWhere(where: WhereForTable<S, TN>): SelectQuery<S, TN, any> {
                // push a new OR group
                this.s.orWhereGroups.push(where);
                return this;
            }

            wherePk(pk: PrimaryKeyValue<S, TN>): SelectQuery<S, TN, any> {
                const pkCols = getPrimaryKeyColumns(table);
                if (!pkCols || pkCols.length === 0) {
                    throw new Error(`Table ${table.name} does not have a primary key`);
                }
                if (pkCols.length === 1) {
                    const colName = pkCols[0];
                    const colDef = findColumn(table, colName);
                    if (pk === null || pk === undefined) {
                        throw new Error(`wherePk on ${table.name} requires a non-null value for primary key column ${colName}`);
                    }
                    if (Array.isArray(pk)) {
                        throw new Error(`wherePk on ${table.name} expects a scalar for primary key column ${colName}, not an array`);
                    }
                    if (isPlainObject(pk)) {
                        throw new Error(`wherePk on ${table.name} expects a scalar for primary key column ${colName}`);
                    }
                    // Runtime type validation against the PK column type
                    validateScalarForColumn(colDef, pk as unknown, `primary key ${table.name}.${colName}`);
                    (this.s.where as any)[colName] = pk as unknown;
                    return this;
                } else {
                    if (!isPlainObject(pk) || pk === null) {
                        throw new Error(`wherePk on ${table.name} requires an object with keys: ${pkCols.join(", ")}`);
                    }
                    const obj = pk as Record<string, unknown>;
                    for (const k of Object.keys(obj)) {
                        if (!pkCols.includes(k)) {
                            throw new Error(`wherePk received unknown key '${k}'. Expected keys: ${pkCols.join(", ")}`);
                        }
                    }
                    for (const colName of pkCols) {
                        if (!(colName in obj)) {
                            throw new Error(`wherePk missing key '${colName}'. Required keys: ${pkCols.join(", ")}`);
                        }
                        const v = obj[colName];
                        if (v === null || v === undefined) {
                            throw new Error(`wherePk on ${table.name} requires non-null values for all primary key columns (${pkCols.join(", ")})`);
                        }
                        if (Array.isArray(v)) {
                            throw new Error(`wherePk on ${table.name} expects scalar values for primary key column ${colName}, not an array`);
                        }
                        const colDef = findColumn(table, colName);
                        validateScalarForColumn(colDef, v, `primary key ${table.name}.${colName}`);
                        (this.s.where as any)[colName] = v;
                    }
                    return this;
                }
            }

      andWhereOp<K extends ColumnNames<S, TN>, O extends WhereOperator>(col: K, op: O, ...args: OpArgsFor<S, TN, K, O>): SelectQuery<S, TN, any>;
      andWhereOp(col: any, op: any, ...args: any[]): SelectQuery<S, TN, any> {
        const value = args[0];
        this.s.andOps.push({ col, op, value });
        return this;
      }
      orWhereOp<K extends ColumnNames<S, TN>, O extends WhereOperator>(col: K, op: O, ...args: OpArgsFor<S, TN, K, O>): SelectQuery<S, TN, any>;
      orWhereOp(col: any, op: any, ...args: any[]): SelectQuery<S, TN, any> {
        const value = args[0];
        this.s.orOpGroups.push([{ col, op, value }]);
        return this;
      }
      andWhereOpGroup(predicates: ReadonlyArray<OpPredicate<S, TN>>): SelectQuery<S, TN, any> {
        const group = (predicates as ReadonlyArray<readonly [ColumnNames<S, TN>, WhereOperator, unknown?]>).map(p => ({ col: p[0], op: p[1], value: p[2] }));
        for (const g of group) this.s.andOps.push(g);
        return this;
      }
      orWhereOpGroup(predicates: ReadonlyArray<OpPredicate<S, TN>>): SelectQuery<S, TN, any> {
        const group = (predicates as ReadonlyArray<readonly [ColumnNames<S, TN>, WhereOperator, unknown?]>).map(p => ({ col: p[0], op: p[1], value: p[2] }));
        this.s.orOpGroups.push(group);
        return this;
      }

      orderBy(order: ReadonlyArray<readonly [ColumnNames<S, TN>, "asc" | "desc"]> | ColumnNames<S, TN>): SelectQuery<S, TN, any> {
        this.s.order = [];
        const isValidDir = (d: string): d is "asc" | "desc" => d === "asc" || d === "desc";
        if (typeof order === "string") {
          // Runtime validation: ensure column exists
          findColumn(table, String(order));
          this.s.order.push({ col: order as ColumnNames<S, TN>, dir: "asc" });
        } else {
          for (const item of order) {
            const col = String(item[0]);
            const dir = String(item[1]);
            // Validate column exists on base table
            findColumn(table, col);
            // Validate direction
            if (!isValidDir(dir)) {
              throw new Error(`Invalid order direction: ${dir}. Allowed: asc | desc`);
            }
            this.s.order.push({ col: item[0], dir: dir });
          }
        }
        return this;
      }

      limit(n: number): SelectQuery<S, TN, any> {
        // Runtime validation: limit must be a non-negative integer
        if (typeof n !== "number" || !Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
          throw new Error(`Invalid limit: ${n}. Limit must be a non-negative integer`);
        }
        this.s.limit = n;
        return this;
      }
      offset(n: number): SelectQuery<S, TN, any> {
        // Runtime validation: offset must be a non-negative integer
        if (typeof n !== "number" || !Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
          throw new Error(`Invalid offset: ${n}. Offset must be a non-negative integer`);
        }
        this.s.offset = n;
        return this;
      }

      join<JT extends TableNames<S>>(tableName: JT, type: "inner" | "left" | "right" | "full" = "inner"): SelectQuery<S, TN, any> {
        const target = findTable(schema, String(tableName));

        // Determine the source table to join from: try most recent join targets first, then earlier ones, then base table
        const sources: TableDef[] = [];
        // Add existing joined targets in reverse order (most recent first)
        for (let i = this.s.joins.length - 1; i >= 0; i--) {
          const src = this.s.joins[i].target;
          if (!sources.some(s => s.name === src.name)) sources.push(src);
        }
        // Finally, add the base table
        if (!sources.some(s => s.name === table.name)) sources.push(table);

        let pickedSource: TableDef | null = null;
        let pairs: { left: string; right: string }[] | null = null;
        for (const src of sources) {
          const p = findJoinOn(src, target);
          if (p && p.length) { pickedSource = src; pairs = p; break; }
        }

        if (!pairs || !pickedSource) {
          const candidates = sources.map(s => s.name).join(", ");
          throw new Error(`No foreign key relation found between any of [${candidates}] and ${target.name}`);
        }

        // Validate join type
        const jt = String(type);
        if (jt !== "inner" && jt !== "left" && jt !== "right" && jt !== "full") {
          throw new Error(`Invalid join type: ${jt}. Allowed: inner | left | right | full`);
        }

        this.s.joins.push({ type: jt as any, source: pickedSource, target, on: pairs });
        return this;
      }

      toSql = (): SqlRequest => {
        const params: Record<string, unknown> = {};
        const type_hints: Record<string, string> = {};
        let p = 0;

        const parts: string[] = [];
        // Columns
        const selectParts: string[] = [];
        if (selected.length === 1 && selected[0] === "*") {
          selectParts.push(`"${table.name}".*`);
        } else {
          // Runtime validation: ensure every selected column exists on the table
          const sel = selected as string[];
          for (const c of sel) {
            // will throw if column not found
            findColumn(table, String(c));
          }
          selectParts.push(sel.map(c => `"${table.name}"."${c}"`).join(", "));
        }
        // Joined table selections
        for (const js of state.joinSelections) {
          if (js.selected.length === 1 && js.selected[0] === "*") {
            selectParts.push(`"${js.target.name}".*`);
          } else {
            const cols = js.selected as string[];
            for (const c of cols) findColumn(js.target, String(c));
            selectParts.push(cols.map(c => `"${js.target.name}"."${c}"`).join(", "));
          }
        }
        parts.push(`select ${selectParts.join(", ")} from "${schema.name}"."${table.name}"`);

        // JOINs
        for (const j of state.joins) {
          const onExpr = j.on.map(p => `"${j.source.name}"."${p.left}" = "${j.target.name}"."${p.right}"`).join(" and ");
          parts.push(`${j.type} join "${schema.name}"."${j.target.name}" on ${onExpr}`);
        }

        // Build WHERE with correct AND/OR semantics:
        // - Collect base AND predicates (equality and operator-based) into one AND group
        // - Collect OR groups (object-based and operator-based) as parenthesized groups
        // - If any OR groups exist, top-level is: (AND-group) or (OR-group1) or (OR-group2) ...
        // - Else, only the AND-group is used

        const andParts: string[] = [];

        // Base AND where (equality style)
        for (const key in state.where) {
          const value = (state.where as any)[key];
          const col = findColumn(table, key);
          p += 1;
          const paramName = `${table.name}_${key}_${p}`;

          if (value === null) {
            if (!col.is_nullable) {
              throw new Error(`Column ${table.name}.${key} is not nullable; cannot compare to null`);
            }
            andParts.push(`"${table.name}"."${key}" is null`);
          } else if (Array.isArray(value) && !isArrayShapedGeomScalarValue(col, value)) {
            // Validate array element types (treat as IN semantics)
            validateInArrayValues(col, key, value as unknown[], "in");
            // IN via = ANY(:param)
            andParts.push(`"${table.name}"."${key}" = ANY(:${paramName})`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          } else {
            // Validate scalar matches column type (note: path/polygon may appear as arrays but represent a single scalar)
            validateScalarForColumn(col, value, `column ${key}`);
            andParts.push(`"${table.name}"."${key}" = :${paramName}`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          }
        }
        // Operator-based AND predicates
        for (const pred of state.andOps) {
          const key = String(pred.col);
          const op = String(pred.op) as WhereOperator;
          const col = findColumn(table, key);
          const qualified = `"${table.name}"."${key}"`;
          if (op === "isnull" || op === "notnull") {
            if (pred.value !== undefined) {
              throw new Error(`Operator ${op} does not take a value for column ${key}`);
            }
            andParts.push(`${qualified} is ${op === "isnull" ? "null" : "not null"}`);
          } else if (op === "in" || op === "notin") {
            const val = pred.value as unknown;
            if (!Array.isArray(val)) {
              throw new Error(`Operator ${op} requires an array value for column ${key}`);
            }
            // Runtime validate each element type for scalar columns
            validateInArrayValues(col, key, val as unknown[], op);
            p += 1;
            const paramName = `${table.name}_${key}_${p}`;
            andParts.push(`${qualified} ${op === "in" ? "= ANY" : "!= ALL"}(:${paramName})`);
            params[paramName] = val;
            addTypeHintForParam(type_hints, paramName, col, val);
          } else if (op === "like" || op === "ilike" || op === "notlike" || op === "notilike") {
            const val = pred.value as unknown;
            if (typeof val !== "string") {
              throw new Error(`Operator ${op} requires a string value for column ${key}`);
            }
            p += 1;
            const paramName = `${table.name}_${key}_${p}`;
            const sqlOp = op === "like" ? "like" : op === "ilike" ? "ilike" : op === "notlike" ? "not like" : "not ilike";
            andParts.push(`${qualified} ${sqlOp} :${paramName}`);
            params[paramName] = val;
            addTypeHintForParam(type_hints, paramName, col, val);
          } else {
            // comparison or equality/inequality
            const val = pred.value as unknown;
            if (val === undefined) throw new Error(`Operator ${op} requires a value for column ${key}`);
            // Runtime type validation against column type
            validateComparisonValue(col, key, val, op);
            p += 1;
            const paramName = `${table.name}_${key}_${p}`;
            if (op === "=") {
              andParts.push(`${qualified} = :${paramName}`);
            } else if (op === "!=") {
              andParts.push(`${qualified} <> :${paramName}`);
            } else if (op === "<" || op === "<=" || op === ">" || op === ">=") {
              andParts.push(`${qualified} ${op} :${paramName}`);
            } else {
              throw new Error(`Unsupported operator: ${op}`);
            }
            params[paramName] = val;
            addTypeHintForParam(type_hints, paramName, col, val);
          }
        }

        // Build OR groups from object-based orWhere
        const orGroupSql: string[] = [];
        for (const group of state.orWhereGroups) {
          const orParts: string[] = [];
          for (const key in group as Record<string, unknown>) {
            const value = (group as any)[key];
            const col = findColumn(table, key);
            p += 1;
            const paramName = `${table.name}_${key}_${p}`;
            if (value === null) {
              if (!col.is_nullable) {
                throw new Error(`Column ${table.name}.${key} is not nullable; cannot compare to null`);
              }
              orParts.push(`"${table.name}"."${key}" is null`);
            } else if (Array.isArray(value) && !isArrayShapedGeomScalarValue(col, value)) {
              // Validate array element types (treat as IN semantics)
              validateInArrayValues(col, key, value as unknown[], "in");
              orParts.push(`"${table.name}"."${key}" = ANY(:${paramName})`);
              params[paramName] = value;
              addTypeHintForParam(type_hints, paramName, col, value);
            } else {
              // Validate scalar matches column type (note: path/polygon may appear as arrays but represent a single scalar)
              validateScalarForColumn(col, value, `column ${key}`);
              orParts.push(`"${table.name}"."${key}" = :${paramName}`);
              params[paramName] = value;
              addTypeHintForParam(type_hints, paramName, col, value);
            }
          }
          if (orParts.length) orGroupSql.push("(" + orParts.join(" or ") + ")");
        }
        // Build OR groups from operator-based orWhereOp groups
        for (const group of state.orOpGroups) {
          const orParts: string[] = [];
          for (const pred of group) {
            const key = String(pred.col);
            const op = String(pred.op) as WhereOperator;
            const col = findColumn(table, key);
            const qualified = `"${table.name}"."${key}"`;
            if (op === "isnull" || op === "notnull") {
              if (pred.value !== undefined) throw new Error(`Operator ${op} does not take a value for column ${key}`);
              orParts.push(`${qualified} is ${op === "isnull" ? "null" : "not null"}`);
            } else if (op === "in" || op === "notin") {
              const val = pred.value as unknown;
              if (!Array.isArray(val)) throw new Error(`Operator ${op} requires an array value for column ${key}`);
              // Runtime validate each element type for scalar columns
              validateInArrayValues(col, key, val as unknown[], op);
              p += 1;
              const paramName = `${table.name}_${key}_${p}`;
              orParts.push(`${qualified} ${op === "in" ? "= ANY" : "!= ALL"}(:${paramName})`);
              params[paramName] = val;
              addTypeHintForParam(type_hints, paramName, col, val);
            } else if (op === "like" || op === "ilike" || op === "notlike" || op === "notilike") {
              const val = pred.value as unknown;
              if (typeof val !== "string") throw new Error(`Operator ${op} requires a string value for column ${key}`);
              p += 1;
              const paramName = `${table.name}_${key}_${p}`;
              const sqlOp = op === "like" ? "like" : op === "ilike" ? "ilike" : op === "notlike" ? "not like" : "not ilike";
              orParts.push(`${qualified} ${sqlOp} :${paramName}`);
              params[paramName] = val;
              addTypeHintForParam(type_hints, paramName, col, val);
            } else {
              const val = pred.value as unknown;
              if (val === undefined) throw new Error(`Operator ${op} requires a value for column ${key}`);
              // Runtime type validation against column type
              validateComparisonValue(col, key, val, op);
              p += 1;
              const paramName = `${table.name}_${key}_${p}`;
              if (op === "=") {
                orParts.push(`${qualified} = :${paramName}`);
              } else if (op === "!=") {
                orParts.push(`${qualified} <> :${paramName}`);
              } else if (op === "<" || op === "<=" || op === ">" || op === ">=") {
                orParts.push(`${qualified} ${op} :${paramName}`);
              } else {
                throw new Error(`Unsupported operator: ${op}`);
              }
              params[paramName] = val;
              addTypeHintForParam(type_hints, paramName, col, val);
            }
          }
          if (orParts.length) orGroupSql.push("(" + orParts.join(" or ") + ")");
        }

        // Compose final WHERE
        if (orGroupSql.length) {
          const andSql = andParts.length ? `(${andParts.join(" and ")})` : "";
          const orSql = orGroupSql.join(" or ");
          const full = andSql ? `${andSql} or ${orSql}` : orSql;
          if (full.trim().length) parts.push("where " + full);
        } else if (andParts.length) {
          parts.push("where " + andParts.join(" and "));
        }

        if (state.order.length) {
          const orders: string[] = [];
          for (const o of state.order) orders.push(`"${table.name}"."${o.col}" ${o.dir}`);
          parts.push("order by " + orders.join(", "));
        }
        if (state.limit !== undefined) parts.push("limit " + state.limit);
        if (state.offset !== undefined) parts.push("offset " + state.offset);

        return {
          q: parts.join(" "),
          params : Object.keys(params).length > 0 ? params: undefined,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }

  insert(values: ValuesForTable<S, TN>): InsertQuery<S, TN> {
    const table = this.table;
    const schema = this.schema;
    const state = { values, returning: [] as ColumnNames<S, TN>[] };

    return new (class implements InsertQuery<S, TN> {
      returning = (cols?: ReadonlyArray<ColumnNames<S, TN>>) => { state.returning = (cols as ColumnNames<S, TN>[] | undefined) || []; return this; };

      toSql = (): SqlRequest => {
        const cols: string[] = [];
        const vals: string[] = [];
        const params: Record<string, unknown> = {};
        const type_hints: Record<string, string> = {};
        let p = 0;

        for (const key in state.values) {
          const value = (state.values as any)[key];
          const col = findColumn(table, key);
          p += 1;
          const paramName = `${table.name}_${key}_${p}`;
          cols.push(`"${key}"`);
          vals.push(`:${paramName}`);
          params[paramName] = value;
          addTypeHintForParam(type_hints, paramName, col, value);
        }

        const parts: string[] = [];
        parts.push(`insert into "${schema.name}"."${table.name}" (${cols.join(", ")}) values (${vals.join(", ")})`);
        if (state.returning.length) parts.push("returning " + state.returning.join(", "));

        return {
          q: parts.join(" "),
          params : Object.keys(params).length > 0 ? params: undefined,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }

  update(values: Partial<ValuesForTable<S, TN>>): UpdateQuery<S, TN> {
    const table = this.table;
    const schema = this.schema;
    const state = { values, where: {} as WhereForTable<S, TN>, returning: [] as ColumnNames<S, TN>[] };

    return new (class implements UpdateQuery<S, TN> {
      where = (w: WhereForTable<S, TN>) => { for (const k in w as Record<string, unknown>) state.where[k as keyof typeof w] = (w as any)[k]; return this; };
      wherePk = (pk: PrimaryKeyValue<S, TN>) => {
        const pkCols = getPrimaryKeyColumns(table);
        if (!pkCols || pkCols.length === 0) throw new Error(`Table ${table.name} does not have a primary key`);
        if (pkCols.length === 1) {
          const colName = pkCols[0];
          const colDef = findColumn(table, colName);
          if (pk === null || pk === undefined) throw new Error(`wherePk on ${table.name} requires a non-null value for primary key column ${colName}`);
          if (Array.isArray(pk)) throw new Error(`wherePk on ${table.name} expects a scalar for primary key column ${colName}, not an array`);
          if (isPlainObject(pk)) throw new Error(`wherePk on ${table.name} expects a scalar for primary key column ${colName}`);
          validateScalarForColumn(colDef, pk as unknown, `primary key ${table.name}.${colName}`);
          (state.where as any)[colName] = pk as unknown;
        } else {
          if (!isPlainObject(pk) || pk === null) throw new Error(`wherePk on ${table.name} requires an object with keys: ${pkCols.join(", ")}`);
          const obj = pk as Record<string, unknown>;
          for (const k of Object.keys(obj)) {
            if (!pkCols.includes(k)) throw new Error(`wherePk received unknown key '${k}'. Expected keys: ${pkCols.join(", ")}`);
          }
          for (const colName of pkCols) {
            if (!(colName in obj)) throw new Error(`wherePk missing key '${colName}'. Required keys: ${pkCols.join(", ")}`);
            const v = obj[colName];
            if (v === null || v === undefined) throw new Error(`wherePk on ${table.name} requires non-null values for all primary key columns (${pkCols.join(", ")})`);
            if (Array.isArray(v)) throw new Error(`wherePk on ${table.name} expects scalar values for primary key column ${colName}, not an array`);
            const colDef = findColumn(table, colName);
            validateScalarForColumn(colDef, v, `primary key ${table.name}.${colName}`);
            (state.where as any)[colName] = v;
          }
        }
        return this;
      };
      returning = (cols?: ReadonlyArray<ColumnNames<S, TN>>) => { state.returning = (cols as ColumnNames<S, TN>[] | undefined) || []; return this; };

      toSql = (): SqlRequest => {
        const params: Record<string, unknown> = {};
        const type_hints: Record<string, string> = {};
        let p = 0;

        const setParts: string[] = [];
        for (const key in state.values) {
          const value = (state.values as any)[key];
          const col = findColumn(table, key);
          p += 1;
          const paramName = `${table.name}_${key}_${p}`;
          setParts.push(`"${key}" = :${paramName}`);
          params[paramName] = value;
          addTypeHintForParam(type_hints, paramName, col, value);
        }

        const whereClauses: string[] = [];
        for (const key in state.where) {
          const value = (state.where as any)[key];
          const col = findColumn(table, key);
          p += 1;
          const paramName = `${table.name}_${key}_${p}`;
          if (value === null) {
            if (!col.is_nullable) {
              throw new Error(`Column ${table.name}.${key} is not nullable; cannot compare to null`);
            }
            whereClauses.push(`"${key}" is null`);
          } else if (Array.isArray(value) && !isArrayShapedGeomScalarValue(col, value)) {
            // Validate array element types (treat as IN semantics)
            validateInArrayValues(col, key, value as unknown[], "in");
            whereClauses.push(`"${key}" = ANY(:${paramName})`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          } else {
            // Validate scalar matches column type (note: path/polygon may appear as arrays but represent a single scalar)
            validateScalarForColumn(col, value, `column ${key}`);
            whereClauses.push(`"${key}" = :${paramName}`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          }
        }

        const parts: string[] = [];
        parts.push(`update "${schema.name}"."${table.name}" set ${setParts.join(", ")}`);
        if (whereClauses.length) parts.push("where " + whereClauses.join(" and "));
        if (state.returning.length) parts.push("returning " + state.returning.join(", "));

        return {
          q: parts.join(" "),
            params : Object.keys(params).length > 0 ? params: undefined,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }

  delete(): DeleteQuery<S, TN> {
    const table = this.table;
    const schema = this.schema;
    const state = { where: {} as WhereForTable<S, TN>, returning: [] as ColumnNames<S, TN>[] };

    return new (class implements DeleteQuery<S, TN> {
      where = (w: WhereForTable<S, TN>) => { for (const k in w as Record<string, unknown>) state.where[k as keyof typeof w] = (w as any)[k]; return this; };
      wherePk = (pk: PrimaryKeyValue<S, TN>) => {
        const pkCols = getPrimaryKeyColumns(table);
        if (!pkCols || pkCols.length === 0) throw new Error(`Table ${table.name} does not have a primary key`);
        if (pkCols.length === 1) {
          const col = pkCols[0];
          if (isPlainObject(pk)) throw new Error(`wherePk on ${table.name} expects a scalar for primary key column ${col}`);
          (state.where as any)[col] = pk as unknown;
        } else {
          if (!isPlainObject(pk)) throw new Error(`wherePk on ${table.name} requires an object with keys: ${pkCols.join(", ")}`);
          const obj = pk as Record<string, unknown>;
          for (const k of Object.keys(obj)) {
            if (!pkCols.includes(k)) throw new Error(`wherePk received unknown key '${k}'. Expected keys: ${pkCols.join(", ")}`);
          }
          for (const col of pkCols) {
            if (!(col in obj)) throw new Error(`wherePk missing key '${col}'. Required keys: ${pkCols.join(", ")}`);
            (state.where as any)[col] = obj[col];
          }
        }
        return this;
      };
      returning = (cols?: ReadonlyArray<ColumnNames<S, TN>>) => { state.returning = (cols as ColumnNames<S, TN>[] | undefined) || []; return this; };

      toSql = (): SqlRequest => {
        const params: Record<string, unknown> = {};
        const type_hints: Record<string, string> = {};
        let p = 0;

        const whereClauses: string[] = [];
        for (const key in state.where) {
          const value = (state.where as any)[key];
          const col = findColumn(table, key);
          p += 1;
          const paramName = `${table.name}_${key}_${p}`;
          if (value === null) {
            if (!col.is_nullable) {
              throw new Error(`Column ${table.name}.${key} is not nullable; cannot compare to null`);
            }
            whereClauses.push(`"${key}" is null`);
          } else if (Array.isArray(value)) {
            // Validate array element types (treat as IN semantics)
            validateInArrayValues(col, key, value as unknown[], "in");
            whereClauses.push(`"${key}" = ANY(:${paramName})`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          } else {
            // Validate scalar matches column type
            validateScalarForColumn(col, value, `column ${key}`);
            whereClauses.push(`"${key}" = :${paramName}`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          }
        }

        const parts: string[] = [];
        parts.push(`delete from "${schema.name}"."${table.name}"`);
        if (whereClauses.length) parts.push("where " + whereClauses.join(" and "));
        if (state.returning.length) parts.push("returning " + state.returning.join(", "));

        return {
          q: parts.join(" "),
          params : Object.keys(params).length > 0 ? params: undefined,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }
}

export function createSqlBuilder<S extends DBSchema>(schema: S): SqlBuilder<S> {
  return {
    table: <TN extends TableNames<S>>(name: TN) => new TableQueryImpl<S, TN>(schema as unknown as DBSchema, String(name)) as unknown as TableQuery<S, TN>,
  };
}
