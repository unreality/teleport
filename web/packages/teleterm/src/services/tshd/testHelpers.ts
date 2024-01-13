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

import * as tsh from './types';

import type { App } from 'teleterm/ui/services/clusters';

export const makeServer = (props: Partial<tsh.Server> = {}): tsh.Server => ({
  uri: '/clusters/teleport-local/servers/1234abcd-1234-abcd-1234-abcd1234abcd',
  tunnel: false,
  name: '1234abcd-1234-abcd-1234-abcd1234abcd',
  hostname: 'foo',
  addr: '127.0.0.1:3022',
  labelsList: [],
  subKind: 'teleport',
  ...props,
});

export const databaseUri = '/clusters/teleport-local/dbs/foo';
export const kubeUri = '/clusters/teleport-local/kubes/foo';

export const makeDatabase = (
  props: Partial<tsh.Database> = {}
): tsh.Database => ({
  uri: databaseUri,
  name: 'foo',
  protocol: 'postgres',
  type: 'self-hosted',
  desc: '',
  hostname: '',
  addr: '',
  labelsList: [],
  ...props,
});

export const makeKube = (props: Partial<tsh.Kube> = {}): tsh.Kube => ({
  name: 'foo',
  labelsList: [],
  uri: '/clusters/bar/kubes/foo',
  ...props,
});

export const makeApp = (props: Partial<tsh.App> = {}): App => ({
  name: 'foo',
  labelsList: [],
  endpointUri: 'tcp://localhost:3000',
  friendlyName: '',
  desc: '',
  awsConsole: false,
  publicAddr: 'local-app.example.com:3000',
  samlApp: false,
  uri: '/clusters/bar/apps/foo',
  addrWithProtocol: 'tcp://local-app.example.com:3000',
  ...props,
});

export const makeLabelsList = (labels: Record<string, string>): tsh.Label[] =>
  Object.entries(labels).map(([name, value]) => ({ name, value }));

export const makeRootCluster = (
  props: Partial<tsh.Cluster> = {}
): tsh.Cluster => ({
  uri: '/clusters/teleport-local',
  name: 'teleport-local',
  connected: true,
  leaf: false,
  proxyHost: 'teleport-local:3080',
  authClusterId: 'fefe3434-fefe-3434-fefe-3434fefe3434',
  loggedInUser: makeLoggedInUser(),
  proxyVersion: '11.1.0',
  ...props,
});

export const makeLeafCluster = (
  props: Partial<tsh.Cluster> = {}
): tsh.Cluster => ({
  uri: '/clusters/teleport-local/leaves/leaf',
  name: 'teleport-local-leaf',
  connected: true,
  leaf: true,
  proxyHost: '',
  authClusterId: '',
  loggedInUser: makeLoggedInUser(),
  proxyVersion: '',
  ...props,
});

export const makeLoggedInUser = (
  props: Partial<tsh.LoggedInUser> = {}
): tsh.LoggedInUser => ({
  activeRequestsList: [],
  assumedRequests: {},
  name: 'alice',
  acl: {
    recordedSessions: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    activeSessions: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    authConnectors: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    roles: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    users: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    trustedClusters: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    events: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    tokens: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    servers: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    apps: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    dbs: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    kubeservers: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
    accessRequests: {
      list: true,
      read: true,
      edit: true,
      create: true,
      pb_delete: true,
      use: true,
    },
  },
  sshLoginsList: [],
  rolesList: [],
  requestableRolesList: [],
  suggestedReviewersList: [],
  userType: tsh.UserType.USER_TYPE_LOCAL,
  ...props,
});

export const makeDatabaseGateway = (
  props: Partial<tsh.Gateway> = {}
): tsh.Gateway => ({
  uri: '/gateways/foo',
  targetName: 'sales-production',
  targetUri: databaseUri,
  targetUser: 'alice',
  localAddress: 'localhost',
  localPort: '1337',
  protocol: 'postgres',
  gatewayCliCommand: {
    path: '/foo/psql',
    argsList: ['psql', 'localhost:1337'],
    envList: [],
    preview: 'psql localhost:1337',
  },
  targetSubresourceName: 'bar',
  ...props,
});

export const makeKubeGateway = (
  props: Partial<tsh.Gateway> = {}
): tsh.Gateway => ({
  uri: '/gateways/foo',
  targetName: 'foo',
  targetUri: kubeUri,
  targetUser: '',
  localAddress: 'localhost',
  localPort: '1337',
  protocol: '',
  gatewayCliCommand: {
    path: '/bin/kubectl',
    argsList: ['version'],
    envList: ['KUBECONFIG=/path/to/kubeconfig'],
    preview: 'KUBECONFIG=/path/to/kubeconfig /bin/kubectl version',
  },
  targetSubresourceName: '',
  ...props,
});

export const makeAppGateway = (
  props: Partial<tsh.Gateway> = {}
): tsh.Gateway => ({
  uri: '/gateways/bar',
  targetName: 'sales-production',
  targetUri: '/clusters/bar/apps/foo',
  localAddress: 'localhost',
  localPort: '1337',
  targetSubresourceName: 'bar',
  gatewayCliCommand: {
    path: '',
    preview: 'curl http://localhost:1337',
    envList: [],
    argsList: [],
  },
  targetUser: '',
  protocol: 'HTTP',
  ...props,
});
