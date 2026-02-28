/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import { CentiaHttpClient } from './http/client';
import type { CentiaClientConfig } from './http/types';
import Schemas from './provisioning/Schemas';
import Columns from './provisioning/Columns';
import Constraints from './provisioning/Constraints';
import Indices from './provisioning/Indices';
import Sequences from './provisioning/Sequences';
import ProvisioningTables from './provisioning/Tables';
import ProvisioningUsers from './provisioning/Users';
import ProvisioningClients from './provisioning/Clients';
import Rules from './provisioning/Rules';
import Privileges from './provisioning/Privileges';
import RpcMethods from './provisioning/RpcMethods';
import MetadataWrite from './provisioning/MetadataWrite';
import TypeScriptInterfaces from './provisioning/TypeScriptInterfaces';
import FileImport from './provisioning/FileImport';
import GitCommit from './provisioning/GitCommit';
import SqlNoToken from './provisioning/SqlNoToken';

/** Admin client providing access to all provisioning operations. */
export interface CentiaAdminClient {
  /** The underlying HTTP client. */
  readonly http: CentiaHttpClient;
  /** Schema, table, column, constraint, index, sequence, user, client, rule, privilege, RPC, metadata, file import, git, and SQL management. */
  readonly provisioning: {
    readonly schemas: Schemas;
    readonly tables: ProvisioningTables;
    readonly columns: Columns;
    readonly constraints: Constraints;
    readonly indices: Indices;
    readonly sequences: Sequences;
    readonly users: ProvisioningUsers;
    readonly clients: ProvisioningClients;
    readonly rules: Rules;
    readonly privileges: Privileges;
    readonly rpcMethods: RpcMethods;
    readonly metadata: MetadataWrite;
    readonly typeScript: TypeScriptInterfaces;
    readonly fileImport: FileImport;
    readonly gitCommit: GitCommit;
    readonly sqlNoToken: SqlNoToken;
  };
}

/**
 * Create a Centia admin client with access to provisioning operations.
 *
 * ```ts
 * const client = createCentiaAdminClient({
 *   baseUrl: 'https://example.centia.io',
 *   auth: { getAccessToken: async () => token },
 * });
 *
 * await client.provisioning.schemas.postSchema({ name: 'myschema' });
 * ```
 */
export function createCentiaAdminClient(config: CentiaClientConfig): CentiaAdminClient {
  const http = new CentiaHttpClient(config);
  return {
    http,
    provisioning: {
      schemas: new Schemas(http),
      tables: new ProvisioningTables(http),
      columns: new Columns(http),
      constraints: new Constraints(http),
      indices: new Indices(http),
      sequences: new Sequences(http),
      users: new ProvisioningUsers(http),
      clients: new ProvisioningClients(http),
      rules: new Rules(http),
      privileges: new Privileges(http),
      rpcMethods: new RpcMethods(http),
      metadata: new MetadataWrite(http),
      typeScript: new TypeScriptInterfaces(http),
      fileImport: new FileImport(http),
      gitCommit: new GitCommit(http),
      sqlNoToken: new SqlNoToken(http),
    },
  };
}
