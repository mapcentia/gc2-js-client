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
import type {RpcRequest, RpcResponse, GqlRequest, GqlResponse, SqlRequest, SqlResponse} from "./types/pgTypes"
import type * as PgTypes from "./types/pgTypes"
import type {Options, CodeFlowOptions, PasswordFlowOptions} from "./util/utils"

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
    PrivilegeLevel,
    PatchPrivilegeRequest,
    PrivilegeInfo,
    TableInfo,
    CreateRpcMethodRequest,
    PatchRpcMethodRequest,
    RpcMethodInfo,
    MetadataFieldInfo,
    MetadataRelationInfo,
    PatchMetadataRequest,
    FileUploadOptions,
    FileProcessRequest,
    FileProcessResponse,
    CommitRequest,
    CommitResult,
} from "./provisioning";
export type { SqlNoTokenRequest } from "./SqlNoToken";
export type { DBSchema, TableDef, ColumnDef, RowForTable, PickRow, RowOfSelect, RowsOfSelect, RowOfRequest, RowsOfRequest } from "./SqlBuilder";
export type { RowOfApiCall, RowsOfApiCall, RowOfApiMethod, RowsOfApiMethod, ParamsOfApiMethod } from "./Api";
