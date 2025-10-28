import type { SqlRequest } from "./types/pgTypes";
import * as PgTypes from "./types/pgTypes";

// Basic schema types (matches provided schema/schema.json shape)
export interface ColumnDef {
  name: string;
  _typname: string; // e.g. int4, varchar, jsonb
  _is_array: boolean;
  is_nullable: boolean;
  type?: string; // e.g. character varying(255)
}

export interface ConstraintDef {
  name: string;
  constraint: "primary" | "foreign" | string;
  columns: readonly string[];
  referenced_table?: string;
  referenced_columns?: readonly string[];
}

export interface TableDef {
  name: string;
  // Use readonly arrays so `as const` schemas preserve literal column names for typing
  columns: readonly ColumnDef[];
  constraints?: readonly ConstraintDef[];
}

export interface DBSchema {
  name: string;
  // Use readonly arrays so `as const` schemas preserve literal table names for typing
  tables: readonly TableDef[];
}

// ---------- Type helpers (best effort) ----------
// Map Postgres typname -> TypeScript value types used by PgTypes
export type ScalarFromTypename<T extends string> =
  T extends "int2" | "int4" | "int8" ? number :
  T extends "float4" | "float8" ? number :
  T extends "numeric" | "decimal" ? PgTypes.NumericString :
  T extends "varchar" | "text" | "bpchar" | "char" ? string :
  T extends "bool" ? PgTypes.PgBoolean :
  T extends "json" | "jsonb" ? PgTypes.JsonValue :
  T extends "date" ? PgTypes.DateString :
  T extends "time" ? PgTypes.TimeString :
  T extends "timetz" ? PgTypes.TimetzString :
  T extends "timestamp" ? PgTypes.TimestampString :
  T extends "timestamptz" ? PgTypes.TimestamptzString :
  unknown;

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

// Value type for a column based on typname and array/nullability flags.
// Note: If schema is not `as const`, flags are not literal and result type becomes broader.
export type ColumnValueFromDef<C extends ColumnDef> =
  C["_is_array"] extends true
    ? PgTypes.PgArray<ScalarFromTypename<C["_typname"]>>
    : ScalarFromTypename<C["_typname"]>;

export type NullableColumnValueFromDef<C extends ColumnDef> =
  C["is_nullable"] extends true ? ColumnValueFromDef<C> | null : ColumnValueFromDef<C>;

export type ValuesForTable<S extends DBSchema, TN extends string> = Partial<{
  [K in ColumnNames<S, TN>]: NullableColumnValueFromDef<Extract<ColumnsOf<S, TN>[number], { name: K }>>
}>;

// Where clause accepts equality and array (= ANY()) semantics.
export type WhereForTable<S extends DBSchema, TN extends string> = Partial<{
  [K in ColumnNames<S, TN>]:
    | NullableColumnValueFromDef<Extract<ColumnsOf<S, TN>[number], { name: K }>>
    | NullableColumnValueFromDef<Extract<ColumnsOf<S, TN>[number], { name: K }>>[]
}>;

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
  // If column is an array OR the value is an Array, we hint as array of the column base type
  const isArr = Array.isArray(value) || col._is_array;
  if (isArr) {
    const hint = typeNameToHint(col._typname, true);
    if (hint) typeHints[paramName] = hint;
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

export interface TableQuery<S extends DBSchema, TN extends string> {
  // SELECT
  select: (cols?: ReadonlyArray<ColumnNames<S, TN>>) => SelectQuery<S, TN>;
  // INSERT
  insert: (values: ValuesForTable<S, TN>) => InsertQuery<S, TN>;
  // UPDATE
  update: (values: Partial<ValuesForTable<S, TN>>) => UpdateQuery<S, TN>;
  // DELETE
  delete: () => DeleteQuery<S, TN>;
}

export interface SelectQuery<S extends DBSchema, TN extends string> {
  where: (where: WhereForTable<S, TN>) => SelectQuery<S, TN>;
  orderBy: (order: ReadonlyArray<readonly [ColumnNames<S, TN>, "asc" | "desc"]> | ColumnNames<S, TN>) => SelectQuery<S, TN>;
  limit: (n: number) => SelectQuery<S, TN>;
  offset: (n: number) => SelectQuery<S, TN>;
  join: <JT extends AllowedJoinTables<S, TN>>(table: JT, type?: "inner" | "left" | "right" | "full") => SelectQuery<S, TN>;
  toSql: () => SqlRequest<Record<string, unknown>>;
}

export interface InsertQuery<S extends DBSchema, TN extends string> {
  returning: (cols?: ReadonlyArray<ColumnNames<S, TN>>) => InsertQuery<S, TN>;
  toSql: () => SqlRequest<Record<string, unknown>>;
}

export interface UpdateQuery<S extends DBSchema, TN extends string> {
  where: (where: WhereForTable<S, TN>) => UpdateQuery<S, TN>;
  returning: (cols?: ReadonlyArray<ColumnNames<S, TN>>) => UpdateQuery<S, TN>;
  toSql: () => SqlRequest<Record<string, unknown>>;
}

export interface DeleteQuery<S extends DBSchema, TN extends string> {
  where: (where: WhereForTable<S, TN>) => DeleteQuery<S, TN>;
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

  select(cols?: ColumnNames<S, TN>[]): SelectQuery<S, TN> {
    const table = this.table;
    const schema = this.schema;
    const selected = (cols && cols.length ? cols : ["*"]) as (ColumnNames<S, TN> | "*")[];
    const state = {
      table,
      selected,
      where: {} as WhereForTable<S, TN>,
      order: [] as { col: ColumnNames<S, TN>; dir: "asc" | "desc" }[],
      limit: undefined as number | undefined,
      offset: undefined as number | undefined,
      joins: [] as { type: "inner" | "left" | "right" | "full"; target: TableDef; on: { left: string; right: string }[] }[],
    };

    return new (class implements SelectQuery<S, TN> {
      private s = state;

      where = (w: WhereForTable<S, TN>) => {
        // merge
        for (const k in w as Record<string, unknown>) this.s.where[k as keyof typeof w] = (w as any)[k];
        return this;
      };

      orderBy = (
        order: (readonly [ColumnNames<S, TN>, "asc" | "desc"])[] | ColumnNames<S, TN>
      ) => {
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
      };

      limit = (n: number) => {
        // Runtime validation: limit must be a non-negative integer
        if (typeof n !== "number" || !Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
          throw new Error(`Invalid limit: ${n}. Limit must be a non-negative integer`);
        }
        this.s.limit = n;
        return this;
      };
      offset = (n: number) => {
        // Runtime validation: offset must be a non-negative integer
        if (typeof n !== "number" || !Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
          throw new Error(`Invalid offset: ${n}. Offset must be a non-negative integer`);
        }
        this.s.offset = n;
        return this;
      };

      join = <JT extends AllowedJoinTables<S, TN>>(tableName: JT, type: "inner" | "left" | "right" | "full" = "inner") => {
        const target = findTable(schema, String(tableName));
        const pairs = findJoinOn(table, target);
        if (!pairs || !pairs.length) throw new Error(`No foreign key relation found between ${table.name} and ${target.name}`);
        // Runtime validation: ensure join type is valid
        const jt = String(type);
        if (jt !== "inner" && jt !== "left" && jt !== "right" && jt !== "full") {
          throw new Error(`Invalid join type: ${jt}. Allowed: inner | left | right | full`);
        }
        this.s.joins.push({ type: jt as any, target, on: pairs });
        return this;
      };

      toSql = (): SqlRequest => {
        const params: Record<string, unknown> = {};
        const type_hints: Record<string, string> = {};
        let p = 0;

        const parts: string[] = [];
        // Columns
        let colsSql: string;
        if (selected.length === 1 && selected[0] === "*") {
          colsSql = `"${table.name}".*`;
        } else {
          // Runtime validation: ensure every selected column exists on the table
          const sel = selected as string[];
          for (const c of sel) {
            // will throw if column not found
            findColumn(table, String(c));
          }
          colsSql = sel.map(c => `"${table.name}"."${c}"`).join(", ");
        }
        parts.push(`select ${colsSql} from "${table.name}"`);

        // JOINs
        for (const j of state.joins) {
          const onExpr = j.on.map(p => `"${table.name}"."${p.left}" = "${j.target.name}"."${p.right}"`).join(" and ");
          parts.push(`${j.type} join "${j.target.name}" on ${onExpr}`);
        }

        const whereClauses: string[] = [];
        for (const key in state.where) {
          const value = (state.where as any)[key];
          const col = findColumn(table, key);
          p += 1;
          const paramName = `${table.name}_${key}_${p}`;

          if (value === null) {
            whereClauses.push(`"${table.name}"."${key}" is null`);
          } else if (Array.isArray(value)) {
            // IN via = ANY(:param)
            whereClauses.push(`"${table.name}"."${key}" = ANY(:${paramName})`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          } else {
            whereClauses.push(`"${table.name}"."${key}" = :${paramName}`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          }
        }
        if (whereClauses.length) parts.push("where " + whereClauses.join(" and "));

        if (state.order.length) {
          const orders: string[] = [];
          for (const o of state.order) orders.push(`"${table.name}"."${o.col}" ${o.dir}`);
          parts.push("order by " + orders.join(", "));
        }
        if (state.limit !== undefined) parts.push("limit " + state.limit);
        if (state.offset !== undefined) parts.push("offset " + state.offset);

        return {
          q: parts.join(" "),
          params,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }

  insert(values: ValuesForTable<S, TN>): InsertQuery<S, TN> {
    const table = this.table;
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
        parts.push(`insert into "${table.name}" (${cols.join(", ")}) values (${vals.join(", ")})`);
        if (state.returning.length) parts.push("returning " + state.returning.join(", "));

        return {
          q: parts.join(" "),
          params,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }

  update(values: Partial<ValuesForTable<S, TN>>): UpdateQuery<S, TN> {
    const table = this.table;
    const state = { values, where: {} as WhereForTable<S, TN>, returning: [] as ColumnNames<S, TN>[] };

    return new (class implements UpdateQuery<S, TN> {
      where = (w: WhereForTable<S, TN>) => { for (const k in w as Record<string, unknown>) state.where[k as keyof typeof w] = (w as any)[k]; return this; };
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
            whereClauses.push(`"${key}" is null`);
          } else if (Array.isArray(value)) {
            whereClauses.push(`"${key}" = ANY(:${paramName})`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          } else {
            whereClauses.push(`"${key}" = :${paramName}`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          }
        }

        const parts: string[] = [];
        parts.push(`update "${table.name}" set ${setParts.join(", ")}`);
        if (whereClauses.length) parts.push("where " + whereClauses.join(" and "));
        if (state.returning.length) parts.push("returning " + state.returning.join(", "));

        return {
          q: parts.join(" "),
          params,
          type_hints: Object.keys(type_hints).length ? type_hints : undefined,
        };
      };
    })();
  }

  delete(): DeleteQuery<S, TN> {
    const table = this.table;
    const state = { where: {} as WhereForTable<S, TN>, returning: [] as ColumnNames<S, TN>[] };

    return new (class implements DeleteQuery<S, TN> {
      where = (w: WhereForTable<S, TN>) => { for (const k in w as Record<string, unknown>) state.where[k as keyof typeof w] = (w as any)[k]; return this; };
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
            whereClauses.push(`"${key}" is null`);
          } else if (Array.isArray(value)) {
            whereClauses.push(`"${key}" = ANY(:${paramName})`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          } else {
            whereClauses.push(`"${key}" = :${paramName}`);
            params[paramName] = value;
            addTypeHintForParam(type_hints, paramName, col, value);
          }
        }

        const parts: string[] = [];
        parts.push(`delete from "${table.name}"`);
        if (whereClauses.length) parts.push("where " + whereClauses.join(" and "));
        if (state.returning.length) parts.push("returning " + state.returning.join(", "));

        return {
          q: parts.join(" "),
          params,
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
