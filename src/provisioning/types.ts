/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

// ===== Shared enums =====

export type ConstraintType = 'primary' | 'foreign' | 'unique' | 'check';
export type IndexMethod = 'btree' | 'brin' | 'gin' | 'gist' | 'hash';
export type IdentityGeneration = 'always' | 'by default';
export type SequenceDataType = 'smallint' | 'integer' | 'bigint';

// ===== Location response (POST 201 / PATCH 303) =====

export interface LocationResponse {
  location: string;
}

// ===== Schema types =====

export interface CreateSchemaRequest {
  name: string;
  tables?: TableDef[];
  sequences?: SequenceDef[];
}

export interface RenameSchemaRequest {
  name: string;
}

export interface GetSchemaOptions {
  namesOnly?: boolean;
}

export interface SchemaInfo {
  name: string;
  tables?: TableInfo[];
  sequences?: SequenceInfo[];
}

// ===== Table types (nested in schema) =====

export interface TableDef {
  name: string;
  columns?: ColumnDef[];
  constraints?: ConstraintDef[];
  indices?: IndexDef[];
  comment?: string;
}

export interface TableInfo {
  name: string;
  columns?: ColumnInfo[];
  constraints?: ConstraintInfo[];
  indices?: IndexInfo[];
  comment?: string;
}

// ===== Column types =====

export interface ColumnDef {
  name?: string;
  type?: string;
  is_nullable?: boolean;
  default_value?: string;
  identity_generation?: IdentityGeneration;
  comment?: string;
}

export interface CreateColumnRequest {
  name: string;
  type: string;
  is_nullable?: boolean;
  default_value?: string;
  identity_generation?: IdentityGeneration;
  comment?: string;
}

export interface PatchColumnRequest {
  name?: string;
  type?: string;
  is_nullable?: boolean;
  default_value?: string;
  identity_generation?: IdentityGeneration;
  comment?: string;
}

export interface ColumnInfo {
  name: string;
  type: string;
  is_nullable: boolean;
  default_value: string | null;
  identity_generation?: string | null;
  comment?: string | null;
  _num?: number;
  _typname?: string;
  _is_array?: boolean;
  _character_maximum_length?: number | null;
  _numeric_precision?: number | null;
  _numeric_scale?: number | null;
  _max_bytes?: number;
  _reference?: string[] | null;
  _is_unique?: boolean;
  _is_primary?: boolean;
  _index_method?: string[] | null;
  _checks?: unknown[] | null;
}

// ===== Constraint types =====

export interface ConstraintDef {
  constraint: ConstraintType;
  columns: string[];
  name?: string;
  check?: string;
  referenced_table?: string;
  referenced_columns?: string[];
}

export interface CreateConstraintRequest {
  constraint: ConstraintType;
  columns: string[];
  name?: string;
  check?: string;
  referenced_table?: string;
  referenced_columns?: string[];
}

export interface ConstraintInfo {
  name: string;
  constraint: ConstraintType;
  columns: string[];
  referenced_table?: string;
  referenced_columns?: string[];
  check?: string;
}

// ===== Index types =====

export interface IndexDef {
  columns: string[];
  method?: IndexMethod;
  name?: string;
}

export interface CreateIndexRequest {
  columns: string[];
  method?: IndexMethod;
  name?: string;
}

export interface IndexInfo {
  name: string;
  method: IndexMethod;
  columns: string[];
  unique?: boolean;
}

// ===== Sequence types =====

export interface SequenceDef {
  name: string;
  data_type?: SequenceDataType;
  increment_by?: number;
  min_value?: number;
  max_value?: number;
  start_value?: number;
  cache_size?: number;
  owned_by?: string;
}

export interface CreateSequenceRequest {
  name: string;
  data_type?: SequenceDataType;
  increment_by?: number;
  min_value?: number;
  max_value?: number;
  start_value?: number;
  cache_size?: number;
  owned_by?: string;
}

export interface PatchSequenceRequest {
  name: string;
  data_type?: SequenceDataType;
  increment_by?: number;
  min_value?: number;
  max_value?: number;
  start_value?: number;
  cache_size?: number;
  owned_by?: string;
}

export interface SequenceInfo {
  name: string;
  data_type: SequenceDataType;
  increment_by: number;
  min_value: number;
  max_value: number;
  start_value: number;
  cache_size: number;
  owned_by?: string;
}
