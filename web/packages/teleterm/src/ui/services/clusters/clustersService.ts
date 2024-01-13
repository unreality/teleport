/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { useStore } from 'shared/libs/stores';
import {
  DbProtocol,
  DbType,
  formatDatabaseInfo,
} from 'shared/services/databases';
import { pipe } from 'shared/utils/pipe';

import * as uri from 'teleterm/ui/uri';
import { NotificationsService } from 'teleterm/ui/services/notifications';
import {
  Cluster,
  Gateway,
  CreateAccessRequestParams,
  GetRequestableRolesParams,
  ReviewAccessRequestParams,
  PromoteAccessRequestParams,
} from 'teleterm/services/tshd/types';
import { MainProcessClient } from 'teleterm/mainProcess/types';
import { UsageService } from 'teleterm/ui/services/usage';

import { ImmutableStore } from '../immutableStore';

import type * as types from './types';
import type * as tsh from 'teleterm/services/tshd/types';

const { routing } = uri;

export function createClusterServiceState(): types.ClustersServiceState {
  return {
    clusters: new Map(),
    gateways: new Map(),
  };
}

export class ClustersService extends ImmutableStore<types.ClustersServiceState> {
  state: types.ClustersServiceState = createClusterServiceState();

  constructor(
    public client: tsh.TshClient,
    private mainProcessClient: MainProcessClient,
    private notificationsService: NotificationsService,
    private usageService: UsageService
  ) {
    super();
  }

  async addRootCluster(addr: string) {
    const cluster = await this.client.addRootCluster(addr);
    this.setState(draft => {
      draft.clusters.set(
        cluster.uri,
        this.removeInternalLoginsFromCluster(cluster)
      );
    });

    return cluster;
  }

  /**
   * Logs out of the cluster and removes the profile.
   * Does not remove the cluster from the state, but sets the cluster and its leafs as disconnected.
   * It needs to be done, because some code can operate on the cluster the intermediate period between logout
   * and actually removing it from the state.
   * A code that operates on that intermediate state is in `useClusterLogout.tsx`.
   * After invoking `logout()`, it looks for the next workspace to switch to. If we hadn't marked the cluster as disconnected,
   * the method might have returned us the same cluster we wanted to log out of.
   */
  async logout(clusterUri: uri.RootClusterUri) {
    // TODO(gzdunek): logout and removeCluster should be combined into a single acton in tshd
    await this.client.logout(clusterUri);
    await this.client.removeCluster(clusterUri);

    this.setState(draft => {
      draft.clusters.forEach(cluster => {
        if (routing.belongsToProfile(clusterUri, cluster.uri)) {
          cluster.connected = false;
        }
      });
    });
  }

  async loginLocal(
    params: types.LoginLocalParams,
    abortSignal: tsh.TshAbortSignal
  ) {
    await this.client.loginLocal(params, abortSignal);
    // We explicitly use the `andCatchErrors` variant here. If loginLocal succeeds but syncing the
    // cluster fails, we don't want to stop the user on the failed modal – we want to open the
    // workspace and show an error state within the workspace.
    await this.syncRootClusterAndCatchErrors(params.clusterUri);
    this.usageService.captureUserLogin(params.clusterUri, 'local');
  }

  async loginSso(
    params: types.LoginSsoParams,
    abortSignal: tsh.TshAbortSignal
  ) {
    await this.client.loginSso(params, abortSignal);
    await this.syncRootClusterAndCatchErrors(params.clusterUri);
    this.usageService.captureUserLogin(params.clusterUri, params.providerType);
  }

  async loginPasswordless(
    params: types.LoginPasswordlessParams,
    abortSignal: tsh.TshAbortSignal
  ) {
    await this.client.loginPasswordless(params, abortSignal);
    await this.syncRootClusterAndCatchErrors(params.clusterUri);
    this.usageService.captureUserLogin(params.clusterUri, 'passwordless');
  }

  /**
   * syncRootClusterAndCatchErrors is useful when the call site doesn't have a UI for handling
   * errors and instead wants to depend on the notifications service.
   */
  async syncRootClusterAndCatchErrors(clusterUri: uri.RootClusterUri) {
    try {
      await this.syncRootCluster(clusterUri);
    } catch (e) {
      const cluster = this.findCluster(clusterUri);
      const clusterName =
        cluster?.name ||
        routing.parseClusterUri(clusterUri).params.rootClusterId;

      this.notificationsService.notifyError({
        title: `Could not synchronize cluster ${clusterName}`,
        description: e.message,
      });
    }
  }

  /**
   * syncRootCluster is useful in situations where we want to sync the cluster _and_ propagate any
   * errors up.
   */
  async syncRootCluster(clusterUri: uri.RootClusterUri) {
    await Promise.all([
      this.syncClusterInfo(clusterUri),
      this.syncLeafClustersList(clusterUri),
    ]);
  }

  async syncRootClustersAndCatchErrors() {
    let clusters: Cluster[];

    try {
      clusters = await this.client.listRootClusters();
    } catch (error) {
      this.notificationsService.notifyError({
        title: 'Could not fetch root clusters',
        description: error.message,
      });
      return;
    }

    this.setState(draft => {
      draft.clusters = new Map(
        clusters.map(c => [c.uri, this.removeInternalLoginsFromCluster(c)])
      );
    });
    clusters
      .filter(c => c.connected)
      .forEach(c => this.syncRootClusterAndCatchErrors(c.uri));
  }

  async syncGatewaysAndCatchErrors() {
    try {
      const gws = await this.client.listGateways();
      this.setState(draft => {
        draft.gateways = new Map(gws.map(g => [g.uri, g]));
      });
    } catch (error) {
      this.notificationsService.notifyError({
        title: 'Could not synchronize database connections',
        description: error.message,
      });
    }
  }

  private async syncLeafClustersList(clusterUri: uri.RootClusterUri) {
    const leaves = await this.client.listLeafClusters(clusterUri);

    this.setState(draft => {
      for (const leaf of leaves) {
        draft.clusters.set(
          leaf.uri,
          this.removeInternalLoginsFromCluster(leaf)
        );
      }
    });

    return leaves;
  }

  async getRequestableRoles(params: GetRequestableRolesParams) {
    const cluster = this.state.clusters.get(params.rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. This check should be done earlier in the
    // UI rather than be repeated in each ClustersService method.
    if (!cluster.connected) {
      return;
    }

    return this.client.getRequestableRoles(params);
  }

  getAssumedRequests(rootClusterUri: uri.RootClusterUri) {
    const cluster = this.state.clusters.get(rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster?.connected) {
      return {};
    }

    return cluster.loggedInUser?.assumedRequests || {};
  }

  getAssumedRequest(rootClusterUri: uri.RootClusterUri, requestId: string) {
    return this.getAssumedRequests(rootClusterUri)[requestId];
  }

  async getAccessRequests(rootClusterUri: uri.RootClusterUri) {
    const cluster = this.state.clusters.get(rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster.connected) {
      return;
    }

    return this.client.getAccessRequests(rootClusterUri);
  }

  async deleteAccessRequest(
    rootClusterUri: uri.RootClusterUri,
    requestId: string
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster.connected) {
      return;
    }
    return this.client.deleteAccessRequest(rootClusterUri, requestId);
  }

  async assumeRole(
    rootClusterUri: uri.RootClusterUri,
    requestIds: string[],
    dropIds: string[]
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster.connected) {
      return;
    }
    await this.client.assumeRole(rootClusterUri, requestIds, dropIds);
    this.usageService.captureAccessRequestAssumeRole(rootClusterUri);
    return this.syncRootCluster(rootClusterUri);
  }

  async getAccessRequest(
    rootClusterUri: uri.RootClusterUri,
    requestId: string
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster.connected) {
      return;
    }

    return this.client.getAccessRequest(rootClusterUri, requestId);
  }

  async reviewAccessRequest(
    rootClusterUri: uri.RootClusterUri,
    params: ReviewAccessRequestParams
  ) {
    const cluster = this.state.clusters.get(rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster.connected) {
      return;
    }

    const response = await this.client.reviewAccessRequest(
      rootClusterUri,
      params
    );
    this.usageService.captureAccessRequestReview(rootClusterUri);
    return response;
  }

  async promoteAccessRequest(params: PromoteAccessRequestParams) {
    const response = await this.client.promoteAccessRequest(params);
    this.usageService.captureAccessRequestReview(params.rootClusterUri);
    return response;
  }

  async createAccessRequest(params: CreateAccessRequestParams) {
    const cluster = this.state.clusters.get(params.rootClusterUri);
    // TODO(ravicious): Remove check for cluster.connected. See the comment in getRequestableRoles.
    if (!cluster.connected) {
      return;
    }

    const response = await this.client.createAccessRequest(params);
    this.usageService.captureAccessRequestCreate(
      params.rootClusterUri,
      params.roles.length ? 'role' : 'resource'
    );
    return response;
  }

  /** Removes cluster, its leafs and other resources. */
  async removeClusterAndResources(clusterUri: uri.RootClusterUri) {
    this.setState(draft => {
      draft.clusters.forEach(cluster => {
        if (routing.belongsToProfile(clusterUri, cluster.uri)) {
          draft.clusters.delete(cluster.uri);
        }
      });
    });
    await this.removeClusterKubeConfigs(clusterUri);
    await this.removeClusterGateways(clusterUri);
  }

  // TODO(ravicious): Create a single RPC for this rather than sending a separate request for each
  // gateway.
  private async removeClusterGateways(clusterUri: uri.RootClusterUri) {
    for (const [, gateway] of this.state.gateways) {
      if (routing.belongsToProfile(clusterUri, gateway.targetUri)) {
        try {
          await this.removeGateway(gateway.uri);
        } catch {
          // Ignore errors as removeGateway already creates a notification for each error.
          // Any gateways that we failed to remove will be forcibly closed on tshd exit.
        }
      }
    }
  }

  async getAuthSettings(clusterUri: uri.RootClusterUri) {
    return (await this.client.getAuthSettings(
      clusterUri
    )) as types.AuthSettings;
  }

  async createGateway(params: tsh.CreateGatewayParams) {
    const gateway = await this.client.createGateway(params);
    this.setState(draft => {
      draft.gateways.set(gateway.uri, gateway);
    });
    return gateway;
  }

  async removeGateway(gatewayUri: uri.GatewayUri) {
    try {
      await this.client.removeGateway(gatewayUri);
      this.setState(draft => {
        draft.gateways.delete(gatewayUri);
      });
    } catch (error) {
      const gateway = this.findGateway(gatewayUri);
      const gatewayDescription = gateway
        ? `for ${gateway.targetUser}@${gateway.targetName}`
        : gatewayUri;
      const title = `Could not close the database connection ${gatewayDescription}`;

      this.notificationsService.notifyError({
        title,
        description: error.message,
      });
      throw error;
    }
  }

  // DELETE IN 15.0.0 (gzdunek),
  // since we will no longer have to support old kube connections.
  // See call in `trackedConnectionOperationsFactory.ts` for more details.
  async removeKubeGateway(kubeUri: uri.KubeUri) {
    const gateway = this.findGatewayByConnectionParams(kubeUri, '');
    if (gateway) {
      await this.removeGateway(gateway.uri);
    }
  }

  async setGatewayTargetSubresourceName(
    gatewayUri: uri.GatewayUri,
    targetSubresourceName: string
  ) {
    if (!this.findGateway(gatewayUri)) {
      throw new Error(`Could not find gateway ${gatewayUri}`);
    }

    const gateway = await this.client.setGatewayTargetSubresourceName(
      gatewayUri,
      targetSubresourceName
    );

    this.setState(draft => {
      draft.gateways.set(gatewayUri, gateway);
    });

    return gateway;
  }

  async setGatewayLocalPort(gatewayUri: uri.GatewayUri, localPort: string) {
    if (!this.findGateway(gatewayUri)) {
      throw new Error(`Could not find gateway ${gatewayUri}`);
    }

    const gateway = await this.client.setGatewayLocalPort(
      gatewayUri,
      localPort
    );

    this.setState(draft => {
      draft.gateways.set(gatewayUri, gateway);
    });

    return gateway;
  }

  findCluster(clusterUri: uri.ClusterUri) {
    return this.state.clusters.get(clusterUri);
  }

  findGateway(gatewayUri: uri.GatewayUri) {
    return this.state.gateways.get(gatewayUri);
  }

  findGatewayByConnectionParams(
    targetUri: uri.GatewayTargetUri,
    targetUser: string
  ) {
    let found: Gateway;

    for (const [, gateway] of this.state.gateways) {
      if (
        gateway.targetUri === targetUri &&
        gateway.targetUser === targetUser
      ) {
        found = gateway;
        break;
      }
    }

    return found;
  }

  /**
   * Returns a root cluster or a leaf cluster to which the given resource belongs to.
   */
  findClusterByResource(uri: uri.ClusterOrResourceUri) {
    const parsed = routing.parseClusterUri(uri);
    if (!parsed) {
      return null;
    }

    const clusterUri = routing.getClusterUri(parsed.params);
    return this.findCluster(clusterUri);
  }

  findRootClusterByResource(uri: string) {
    const parsed = routing.parseClusterUri(uri);
    if (!parsed) {
      return null;
    }

    const rootClusterUri = routing.getClusterUri({
      rootClusterId: parsed.params.rootClusterId,
    });
    return this.findCluster(rootClusterUri);
  }

  getClusters() {
    return [...this.state.clusters.values()];
  }

  getRootClusters() {
    return this.getClusters().filter(c => !c.leaf);
  }

  async removeClusterKubeConfigs(clusterUri: string): Promise<void> {
    const {
      params: { rootClusterId },
    } = routing.parseClusterUri(clusterUri);
    return this.mainProcessClient.removeKubeConfig({
      relativePath: rootClusterId,
      isDirectory: true,
    });
  }

  async removeKubeConfig(kubeConfigRelativePath: string): Promise<void> {
    return this.mainProcessClient.removeKubeConfig({
      relativePath: kubeConfigRelativePath,
    });
  }

  useState() {
    return useStore(this).state;
  }

  private async syncClusterInfo(clusterUri: uri.RootClusterUri) {
    const cluster = await this.client.getCluster(clusterUri);
    // TODO: this information should eventually be gathered by getCluster
    const assumedRequests = cluster.loggedInUser
      ? await this.fetchClusterAssumedRequests(
          cluster.loggedInUser.activeRequestsList,
          clusterUri
        )
      : undefined;
    const mergeAssumedRequests = (cluster: Cluster) => ({
      ...cluster,
      loggedInUser: cluster.loggedInUser && {
        ...cluster.loggedInUser,
        assumedRequests,
      },
    });
    const processCluster = pipe(
      this.removeInternalLoginsFromCluster,
      mergeAssumedRequests
    );

    this.setState(draft => {
      draft.clusters.set(clusterUri, processCluster(cluster));
    });
  }

  private async fetchClusterAssumedRequests(
    activeRequestsList: string[],
    clusterUri: uri.RootClusterUri
  ) {
    return (
      await Promise.all(
        activeRequestsList.map(requestId =>
          this.getAccessRequest(clusterUri, requestId)
        )
      )
    ).reduce((requestsMap, request) => {
      requestsMap[request.id] = {
        id: request.id,
        expires: new Date(request.expires.seconds * 1000),
        roles: request.rolesList,
      };
      return requestsMap;
    }, {});
  }

  // temporary fix for https://github.com/gravitational/webapps.e/issues/294
  // remove when it will get fixed in `tsh`
  // alternatively, show only valid logins basing on RBAC check
  private removeInternalLoginsFromCluster(cluster: Cluster): Cluster {
    return {
      ...cluster,
      loggedInUser: cluster.loggedInUser && {
        ...cluster.loggedInUser,
        sshLoginsList: cluster.loggedInUser.sshLoginsList.filter(
          login => !login.startsWith('-')
        ),
      },
    };
  }
}

export function makeServer(source: tsh.Server) {
  return {
    uri: source.uri,
    id: source.name,
    clusterId: source.name,
    hostname: source.hostname,
    labels: source.labelsList,
    addr: source.addr,
    tunnel: source.tunnel,
    sshLogins: [],
  };
}

export function makeDatabase(source: tsh.Database) {
  return {
    uri: source.uri,
    name: source.name,
    description: source.desc,
    type: formatDatabaseInfo(
      source.type as DbType,
      source.protocol as DbProtocol
    ).title,
    protocol: source.protocol,
    labels: source.labelsList,
  };
}

export function makeKube(source: tsh.Kube) {
  return {
    uri: source.uri,
    name: source.name,
    labels: source.labelsList,
  };
}

export interface App extends tsh.App {
  /**
   * `addrWithProtocol` is an app protocol + a public address.
   * If the public address is empty, it falls back to the endpoint URI.
   *
   * Always empty for SAML applications.
   */
  addrWithProtocol: string;
}

export function makeApp(source: tsh.App): App {
  const { publicAddr, endpointUri } = source;

  const isTcp = endpointUri && endpointUri.startsWith('tcp://');
  const isCloud = endpointUri && endpointUri.startsWith('cloud://');
  let addrWithProtocol = endpointUri;
  if (publicAddr) {
    if (isCloud) {
      addrWithProtocol = `cloud://${publicAddr}`;
    } else if (isTcp) {
      addrWithProtocol = `tcp://${publicAddr}`;
    } else {
      addrWithProtocol = `https://${publicAddr}`;
    }
  }

  return { ...source, addrWithProtocol };
}
