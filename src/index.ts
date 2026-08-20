/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import CodeFlow from "./CodeFlow"
import PasswordFlow from "./PasswordFlow"
import Sql from "./Sql"
import SqlNoToken from "./SqlNoToken"
import Rpc from "./Rpc"
import Gql from "./Gql"
import Meta from "./Meta"
import Status from "./Status"
import Claims from "./Claims"
import Users from "./Users"
import Ws from "./Ws"
import Stats from "./Stats"
import Tables from "./Tables"
import createApi from "./Api"
import SignUp from "./SignUp"
import { createSqlBuilder } from "./SqlBuilder"
import { createCentiaClient } from "./http/client"
import { CentiaApiError, isCentiaApiError } from "./http/errors"
import { createCentiaAdminClient } from "./admin"
import { Ows } from "./ogc/Ows"
import { Wfs } from "./ogc/Wfs"
import { Mapcache } from "./ogc/Mapcache"
import { Keyvalue } from "./keyvalue/Keyvalue"
import type {RpcRequest, RpcResponse, GqlRequest, GqlResponse, SqlRequest, SqlResponse} from "./types/pgTypes"
import type * as PgTypes from "./types/pgTypes"
import type {Options, CodeFlowOptions, PasswordFlowOptions} from "./util/utils"
import type {WsOptions, WsMessage, BatchMessage, SubscriptionAckMessage, WsErrorMessage, SubscriptionRequest, TableBatch} from "./Ws"

export {
    CodeFlow,
    PasswordFlow,
    Sql,
    SqlNoToken,
    Rpc,
    Gql,
    Meta,
    Status,
    Claims,
    Users,
    Ws,
    Stats,
    Tables,
    createApi,
    SignUp,
    createSqlBuilder,
    createCentiaClient,
    createCentiaAdminClient,
    Ows,
    Wfs,
    Mapcache,
    Keyvalue,
    CentiaApiError,
    isCentiaApiError,
}

export type {
    RpcRequest,
    RpcResponse,
    SqlRequest,
    SqlResponse,
    GqlRequest,
    GqlResponse,
    Options,
    CodeFlowOptions,
    PasswordFlowOptions,
    WsOptions,
    WsMessage,
    BatchMessage,
    SubscriptionAckMessage,
    WsErrorMessage,
    SubscriptionRequest,
    TableBatch,
    PgTypes,
}

export type { CentiaClientConfig, CentiaAuth, RequestOptions, FullResponse } from "./http/types";
export type { CentiaApiErrorOptions } from "./http/errors";
export type { CentiaHttpClient } from "./http/client";
export type { CentiaAdminClient } from "./admin";
export type {
    LocationResponse,
    CreateSchemaRequest,
    RenameSchemaRequest,
    GetSchemaOptions,
    SchemaInfo,
    CreateColumnRequest,
    PatchColumnRequest,
    ColumnInfo,
    CreateConstraintRequest,
    ConstraintInfo,
    CreateIndexRequest,
    IndexInfo,
    CreateSequenceRequest,
    PatchSequenceRequest,
    SequenceInfo,
    CreateUserRequest,
    PatchUserRequest,
    UserInfo,
    CreateClientRequest,
    PatchClientRequest,
    CreateClientResponse,
    ClientInfo,
    RuleAccess,
    RuleRequest,
    RuleService,
    CreateRuleRequest,
    PatchRuleRequest,
    RuleInfo,
    LayerGeotype,
    LayerTileFormat,
    LayerCacheType,
    LabelPosition,
    FontWeight,
    LineCap,
    GeomTransform,
    LayerProperties,
    Style,
    Label,
    LayerClass,
    Layer,
    GetLayerOptions,
    MapConfig,
    PrivilegeLevel,
    PatchPrivilegeRequest,
    PrivilegeInfo,
    TableInfo,
    CreateRpcMethodRequest,
    PatchRpcMethodRequest,
    RpcMethodInfo,
    FunctionRuntime,
    FunctionPackage,
    FunctionStatus,
    FunctionEventOp,
    FunctionTriggers,
    CreateFunctionRequest,
    PatchFunctionRequest,
    FunctionInfo,
    FunctionInvocationResult,
    AsyncInvocationAccepted,
    DryRunResult,
    FunctionInvocationRecord,
    MetadataFieldInfo,
    MetadataRelationInfo,
    PatchMetadataRequest,
    FileUploadOptions,
    FileProcessRequest,
    FileProcessResponse,
    CommitRequest,
    CommitResult,
} from "./provisioning";
export type { OwsParams } from "./ogc/Ows";
export type { WfsGetParams, WfsPathOptions } from "./ogc/Wfs";
export type { MapcacheParams, DeleteMapcacheTilesetOptions, MapcacheTilesetDeleteResult } from "./ogc/Mapcache";
export type { KeyvalueEntry, CreateKeyvalueRequest, PatchKeyvalueRequest, KeyvalueProjection } from "./keyvalue/Keyvalue";
export type { SqlNoTokenRequest } from "./SqlNoToken";
export type { DBSchema, TableDef, ColumnDef, RowForTable, PickRow, RowOfSelect, RowsOfSelect, RowOfRequest, RowsOfRequest } from "./SqlBuilder";
export type { RowOfApiCall, RowsOfApiCall, RowOfApiMethod, RowsOfApiMethod, ParamsOfApiMethod } from "./Api";

export {
    createTokenProvider,
    NotLoggedInError,
    SessionExpiredError,
} from './auth'
export type {
    StoredCredentials,
    TokenStore,
    TokenProvider,
    AuthService,
    CreateTokenProviderOptions,
} from './auth'
