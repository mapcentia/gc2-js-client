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

export interface GetTableOptions {
  namesOnly?: boolean;
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

// ===== User types =====

export interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
  default_user?: boolean;
  properties?: unknown;
}

export interface PatchUserRequest {
  email: string;
  password: string | null;
  default_user?: boolean;
  properties?: unknown;
  user_group?: string;
}

export interface UserInfo {
  name: string;
  email: string;
  default_user: boolean;
  user_group?: string;
  properties?: unknown;
}

// ===== OAuth Client types =====

export interface CreateClientRequest {
  name: string;
  id?: string;
  description?: string | null;
  redirect_uri?: string[];
  homepage?: string;
  public?: boolean;
  confirm?: boolean;
  two_factor?: boolean;
  allow_signup?: boolean;
  social_signup?: boolean;
}

export interface PatchClientRequest {
  name?: string;
  description?: string | null;
  redirect_uri?: string[];
  homepage?: string;
  public?: boolean;
  confirm?: boolean;
  two_factor?: boolean;
  allow_signup?: boolean;
  social_signup?: boolean;
}

export interface CreateClientResponse {
  location: string;
  secret: string;
}

export interface ClientInfo {
  id: string;
  name: string;
  description: string | null;
  redirect_uri: string[];
  homepage: string;
  public: boolean;
  confirm: boolean;
  two_factor: boolean;
  allow_signup: boolean;
  social_signup: boolean;
}

// ===== Access Rule types =====

export type RuleAccess = 'allow' | 'limit' | 'deny';
export type RuleRequest = 'select' | 'insert' | 'update' | 'delete';
export type RuleService = 'sql' | 'ows' | 'wfst';

export interface CreateRuleRequest {
  access?: RuleAccess;
  filter?: string;
  id?: number;
  iprange?: string;
  priority?: number;
  request?: RuleRequest;
  schema?: string;
  service?: RuleService;
  table?: string;
  username?: string;
}

export interface PatchRuleRequest {
  access?: RuleAccess;
  filter?: string;
  iprange?: string;
  priority?: number;
  request?: RuleRequest;
  schema?: string;
  service?: RuleService;
  table?: string;
  username?: string;
}

export interface RuleInfo {
  id: number;
  access?: RuleAccess;
  filter?: string;
  iprange?: string;
  priority?: number;
  request?: RuleRequest;
  schema?: string;
  service?: RuleService;
  table?: string;
  username?: string;
}

// ===== Privilege types =====

export type PrivilegeLevel = 'none' | 'read' | 'write';

export interface PatchPrivilegeRequest {
  subuser: string;
  privilege: PrivilegeLevel;
}

export interface PrivilegeInfo {
  subuser: string;
  privilege: PrivilegeLevel;
}

// ===== RPC Method types =====

export interface CreateRpcMethodRequest {
  method: string;
  q: string;
  output_format?: string;
  srs?: number;
  type_formats?: Record<string, unknown>;
  type_hints?: Record<string, unknown>;
}

export interface PatchRpcMethodRequest {
  q: string;
  output_format?: string;
  srs?: number;
  type_formats?: Record<string, unknown>;
  type_hints?: Record<string, unknown>;
}

export interface RpcMethodInfo {
  method: string;
  q: string;
  output_format?: string;
  srs?: number;
  type_formats?: Record<string, unknown>;
  type_hints?: Record<string, unknown>;
}

// ===== Metadata types =====

export interface MetadataFieldInfo {
  // `null` clears the field; the API accepts it, so allow it here.
  alias?: string | null;
  queryable?: boolean;
  sort_id?: number | null;
}

export interface MetadataRelationInfo {
  // `null` clears the field; the API accepts it, so allow it here.
  title?: string | null;
  abstract?: string | null;
  group?: string | null;
  sort_id?: number | null;
  tags?: string[] | null;
  properties?: Record<string, unknown> | null;
  fields?: Record<string, MetadataFieldInfo>;
}

export interface PatchMetadataRequest {
  relations: Record<string, MetadataRelationInfo>;
}

// ===== File Import types =====

export interface FileUploadOptions {
  chunkSize?: number;
}

export interface FileProcessRequest {
  file: string;
  schema: string;
  import?: boolean;
  append?: boolean;
  truncate?: boolean;
  p_multi?: boolean;
  s_srs?: string;
  t_srs?: string;
  timestamp?: string;
  x_possible_names?: string;
  y_possible_names?: string;
}

export interface FileProcessResponse {
  driver: string;
  count: number;
  geom_type: string;
  index: number;
  name: string;
  has_wkt: boolean;
  auth_str: string;
  error: string;
}

// ===== Layer types =====

export type LayerGeotype = 'Default' | 'POINT' | 'LINE' | 'POLYGON';
export type LayerTileFormat = 'PNG' | 'jpeg_low' | 'jpeg_medium' | 'jpeg_high';
export type LayerCacheType = 'disk' | 'sqlite' | 's3' | 'memcache';
export type LabelPosition = 'auto' | 'ul' | 'uc' | 'ur' | 'cl' | 'cc' | 'cr' | 'll' | 'lc' | 'lr';
export type FontWeight = 'normal' | 'bold' | 'italic' | 'bolditalic';
export type LineCap = 'round' | 'butt' | 'square';
export type GeomTransform = 'bbox' | 'centroid' | 'end' | 'labelpnt' | 'labelpoly' | 'start' | 'vertices';

/** Layer properties (the def JSON). Numeric values are stored as strings, empty string when unset. */
export interface LayerProperties {
  theme_column?: string;
  label_column?: string;
  opacity?: string;
  label_max_scale?: string;
  label_min_scale?: string;
  cluster?: string;
  meta_tiles?: string;
  meta_size?: string;
  meta_buffer?: string;
  ttl?: string;
  auto_expire?: string;
  maxscaledenom?: string;
  minscaledenom?: string;
  symbolscaledenom?: string;
  geotype?: LayerGeotype;
  offsite?: string;
  format?: LayerTileFormat;
  lock?: boolean;
  layers?: string;
  bands?: string;
  cache?: LayerCacheType;
  s3_tile_set?: string;
  label_no_clip?: boolean;
  polyline_no_clip?: boolean;
}

/** Style entry of a class. Property keys follow MapServer STYLE parameters. */
export interface Style {
  id?: string;
  sortid?: number;
  name?: string;
  color?: string;
  width?: string;
  outlinecolor?: string;
  symbol?: string;
  size?: string;
  angle?: string;
  gap?: string;
  opacity?: string;
  pattern?: string;
  linecap?: LineCap;
  geomtransform?: GeomTransform;
  minsize?: string;
  maxsize?: string;
  offsetx?: string;
  offsety?: string;
  polaroffsetr?: string;
  polaroffsetd?: string;
}

/** Label entry of a class. Property keys follow MapServer LABEL parameters. */
export interface Label {
  id?: string;
  sortid?: number;
  name?: string;
  on?: boolean;
  text?: string;
  force?: boolean;
  minscaledenom?: string;
  maxscaledenom?: string;
  position?: LabelPosition;
  size?: string;
  color?: string;
  outlinecolor?: string;
  buffer?: string;
  repeatdistance?: string;
  angle?: string;
  backgroundcolor?: string;
  backgroundpadding?: string;
  offsetx?: string;
  offsety?: string;
  font?: string;
  fontweight?: FontWeight;
  expression?: string;
  maxsize?: string;
  minfeaturesize?: string;
}

/** Class definition with styles and labels. */
export interface LayerClass {
  id?: string;
  name?: string;
  sortid?: number;
  expression?: string;
  styles?: Style[];
  labels?: Label[];
  minscaledenom?: string;
  maxscaledenom?: string;
  leader?: boolean;
  leader_gridstep?: string;
  leader_maxdistance?: string;
  leader_color?: string;
}

/** Layer definition: properties (the def JSON) and classes with styles and labels. */
export interface Layer {
  /** Layer key: schema.table.geometry_column. */
  name: string;
  properties?: LayerProperties;
  classes?: LayerClass[];
}

export interface GetLayerOptions {
  /** Return only layer keys. */
  namesOnly?: boolean;
}

// ===== Git Commit types =====

export interface CommitRequest {
  schema: string;
  repo: string;
  message: string;
  meta_query?: string;
}

export interface CommitResult {
  [key: string]: unknown;
}
