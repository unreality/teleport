// GENERATED CODE -- DO NOT EDIT!

// Original file comments:
//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
'use strict';
var grpc = require('@grpc/grpc-js');
var teleport_lib_teleterm_v1_service_pb = require('../../../../teleport/lib/teleterm/v1/service_pb.js');
var teleport_accesslist_v1_accesslist_pb = require('../../../../teleport/accesslist/v1/accesslist_pb.js');
var teleport_lib_teleterm_v1_access_request_pb = require('../../../../teleport/lib/teleterm/v1/access_request_pb.js');
var teleport_lib_teleterm_v1_app_pb = require('../../../../teleport/lib/teleterm/v1/app_pb.js');
var teleport_lib_teleterm_v1_auth_settings_pb = require('../../../../teleport/lib/teleterm/v1/auth_settings_pb.js');
var teleport_lib_teleterm_v1_cluster_pb = require('../../../../teleport/lib/teleterm/v1/cluster_pb.js');
var teleport_lib_teleterm_v1_database_pb = require('../../../../teleport/lib/teleterm/v1/database_pb.js');
var teleport_lib_teleterm_v1_gateway_pb = require('../../../../teleport/lib/teleterm/v1/gateway_pb.js');
var teleport_lib_teleterm_v1_kube_pb = require('../../../../teleport/lib/teleterm/v1/kube_pb.js');
var teleport_lib_teleterm_v1_server_pb = require('../../../../teleport/lib/teleterm/v1/server_pb.js');
var teleport_lib_teleterm_v1_usage_events_pb = require('../../../../teleport/lib/teleterm/v1/usage_events_pb.js');
var teleport_userpreferences_v1_cluster_preferences_pb = require('../../../../teleport/userpreferences/v1/cluster_preferences_pb.js');
var teleport_userpreferences_v1_unified_resource_preferences_pb = require('../../../../teleport/userpreferences/v1/unified_resource_preferences_pb.js');

function serialize_teleport_lib_teleterm_v1_AddClusterRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.AddClusterRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.AddClusterRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_AddClusterRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.AddClusterRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_AssumeRoleRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.AssumeRoleRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.AssumeRoleRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_AssumeRoleRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.AssumeRoleRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_AuthSettings(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_auth_settings_pb.AuthSettings)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.AuthSettings');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_AuthSettings(buffer_arg) {
  return teleport_lib_teleterm_v1_auth_settings_pb.AuthSettings.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_Cluster(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_cluster_pb.Cluster)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.Cluster');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_Cluster(buffer_arg) {
  return teleport_lib_teleterm_v1_cluster_pb.Cluster.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateAccessRequestRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateAccessRequestRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateAccessRequestRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateAccessRequestRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateAccessRequestRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateAccessRequestResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateAccessRequestResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateAccessRequestResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateAccessRequestResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateAccessRequestResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerNodeTokenRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateConnectMyComputerNodeTokenRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerNodeTokenRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerNodeTokenResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateConnectMyComputerNodeTokenResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerNodeTokenResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerRoleRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateConnectMyComputerRoleRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerRoleRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerRoleResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateConnectMyComputerRoleResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerRoleResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_CreateGatewayRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.CreateGatewayRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.CreateGatewayRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_CreateGatewayRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.CreateGatewayRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_DeleteAccessRequestRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.DeleteAccessRequestRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.DeleteAccessRequestRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_DeleteAccessRequestRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.DeleteAccessRequestRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerNodeRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.DeleteConnectMyComputerNodeRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerNodeRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerNodeResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.DeleteConnectMyComputerNodeResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerNodeResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerTokenRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.DeleteConnectMyComputerTokenRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerTokenRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerTokenResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.DeleteConnectMyComputerTokenResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerTokenResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_EmptyResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.EmptyResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.EmptyResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_EmptyResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.EmptyResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_FileTransferProgress(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.FileTransferProgress)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.FileTransferProgress');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_FileTransferProgress(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.FileTransferProgress.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_FileTransferRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.FileTransferRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.FileTransferRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_FileTransferRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.FileTransferRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_Gateway(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_gateway_pb.Gateway)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.Gateway');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_Gateway(buffer_arg) {
  return teleport_lib_teleterm_v1_gateway_pb.Gateway.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAccessRequestRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAccessRequestRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAccessRequestRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAccessRequestRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAccessRequestRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAccessRequestResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAccessRequestResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAccessRequestResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAccessRequestResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAccessRequestResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAccessRequestsRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAccessRequestsRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAccessRequestsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAccessRequestsRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAccessRequestsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAccessRequestsResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAccessRequestsResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAccessRequestsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAccessRequestsResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAccessRequestsResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAppsRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAppsRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAppsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAppsRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAppsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAppsResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAppsResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAppsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAppsResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAppsResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetAuthSettingsRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetAuthSettingsRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetAuthSettingsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetAuthSettingsRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetAuthSettingsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetClusterRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetClusterRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetClusterRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetClusterRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetClusterRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetConnectMyComputerNodeNameRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetConnectMyComputerNodeNameRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetConnectMyComputerNodeNameRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetConnectMyComputerNodeNameResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetConnectMyComputerNodeNameResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetConnectMyComputerNodeNameResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetDatabasesRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetDatabasesRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetDatabasesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetDatabasesRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetDatabasesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetDatabasesResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetDatabasesResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetDatabasesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetDatabasesResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetDatabasesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetKubesRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetKubesRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetKubesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetKubesRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetKubesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetKubesResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetKubesResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetKubesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetKubesResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetKubesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetRequestableRolesRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetRequestableRolesRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetRequestableRolesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetRequestableRolesRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetRequestableRolesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetRequestableRolesResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetRequestableRolesResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetRequestableRolesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetRequestableRolesResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetRequestableRolesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetServersRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetServersRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetServersRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetServersRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetServersRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetServersResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetServersResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetServersResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetServersResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetServersResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetSuggestedAccessListsRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetSuggestedAccessListsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetSuggestedAccessListsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetSuggestedAccessListsResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetSuggestedAccessListsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetSuggestedAccessListsResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetUserPreferencesRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetUserPreferencesRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetUserPreferencesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetUserPreferencesRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetUserPreferencesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_GetUserPreferencesResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.GetUserPreferencesResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.GetUserPreferencesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_GetUserPreferencesResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.GetUserPreferencesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListClustersRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListClustersRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListClustersRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListClustersRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListClustersRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListClustersResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListClustersResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListClustersResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListClustersResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListClustersResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListDatabaseUsersRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListDatabaseUsersRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListDatabaseUsersRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListDatabaseUsersRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListDatabaseUsersRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListDatabaseUsersResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListDatabaseUsersResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListDatabaseUsersResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListDatabaseUsersResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListDatabaseUsersResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListGatewaysRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListGatewaysRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListGatewaysRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListGatewaysRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListGatewaysRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListGatewaysResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListGatewaysResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListGatewaysResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListGatewaysResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListGatewaysResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListLeafClustersRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListLeafClustersRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListLeafClustersRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListLeafClustersRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListLeafClustersRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListUnifiedResourcesRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListUnifiedResourcesRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListUnifiedResourcesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListUnifiedResourcesRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListUnifiedResourcesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ListUnifiedResourcesResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ListUnifiedResourcesResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ListUnifiedResourcesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ListUnifiedResourcesResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ListUnifiedResourcesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_LoginPasswordlessRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.LoginPasswordlessRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.LoginPasswordlessRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_LoginPasswordlessRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.LoginPasswordlessRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_LoginPasswordlessResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.LoginPasswordlessResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.LoginPasswordlessResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_LoginPasswordlessResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.LoginPasswordlessResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_LoginRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.LoginRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.LoginRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_LoginRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.LoginRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_LogoutRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.LogoutRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.LogoutRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_LogoutRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.LogoutRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_PromoteAccessRequestRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.PromoteAccessRequestRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.PromoteAccessRequestRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_PromoteAccessRequestRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.PromoteAccessRequestRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_PromoteAccessRequestResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.PromoteAccessRequestResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.PromoteAccessRequestResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_PromoteAccessRequestResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.PromoteAccessRequestResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_RemoveClusterRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.RemoveClusterRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.RemoveClusterRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_RemoveClusterRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.RemoveClusterRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_RemoveGatewayRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.RemoveGatewayRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.RemoveGatewayRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_RemoveGatewayRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.RemoveGatewayRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ReportUsageEventRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_usage_events_pb.ReportUsageEventRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ReportUsageEventRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ReportUsageEventRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_usage_events_pb.ReportUsageEventRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ReviewAccessRequestRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ReviewAccessRequestRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ReviewAccessRequestRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ReviewAccessRequestRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ReviewAccessRequestRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_ReviewAccessRequestResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.ReviewAccessRequestResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.ReviewAccessRequestResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_ReviewAccessRequestResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.ReviewAccessRequestResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_SetGatewayLocalPortRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.SetGatewayLocalPortRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.SetGatewayLocalPortRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_SetGatewayLocalPortRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.SetGatewayLocalPortRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_SetGatewayTargetSubresourceNameRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.SetGatewayTargetSubresourceNameRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.SetGatewayTargetSubresourceNameRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_SetGatewayTargetSubresourceNameRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.SetGatewayTargetSubresourceNameRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.UpdateHeadlessAuthenticationStateRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.UpdateHeadlessAuthenticationStateRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.UpdateHeadlessAuthenticationStateRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.UpdateHeadlessAuthenticationStateResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.UpdateHeadlessAuthenticationStateResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.UpdateHeadlessAuthenticationStateResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.UpdateTshdEventsServerAddressRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.UpdateTshdEventsServerAddressRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.UpdateTshdEventsServerAddressRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.UpdateTshdEventsServerAddressResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.UpdateTshdEventsServerAddressResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.UpdateTshdEventsServerAddressResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_UpdateUserPreferencesRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.UpdateUserPreferencesRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.UpdateUserPreferencesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_UpdateUserPreferencesRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.UpdateUserPreferencesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_UpdateUserPreferencesResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.UpdateUserPreferencesResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.UpdateUserPreferencesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_UpdateUserPreferencesResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.UpdateUserPreferencesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinRequest(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.WaitForConnectMyComputerNodeJoinRequest)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.WaitForConnectMyComputerNodeJoinRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinRequest(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.WaitForConnectMyComputerNodeJoinRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinResponse(arg) {
  if (!(arg instanceof teleport_lib_teleterm_v1_service_pb.WaitForConnectMyComputerNodeJoinResponse)) {
    throw new Error('Expected argument of type teleport.lib.teleterm.v1.WaitForConnectMyComputerNodeJoinResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinResponse(buffer_arg) {
  return teleport_lib_teleterm_v1_service_pb.WaitForConnectMyComputerNodeJoinResponse.deserializeBinary(new Uint8Array(buffer_arg));
}


// TerminalService is used by the Electron app to communicate with the tsh daemon.
//
// While we aim to preserve backwards compatibility in order to satisfy CI checks and follow the
// proto practices used within the company, this service is not guaranteed to be stable across
// versions. The packaging process of Teleport Connect ensures that the server and the client use
// the same version of the service.
var TerminalServiceService = exports.TerminalServiceService = {
  // UpdateTshdEventsServerAddress lets the Electron app update the address the tsh daemon is
// supposed to use when connecting to the tshd events gRPC service. This RPC needs to be made
// before any other from this service.
//
// The service is supposed to return a response from this call only after the client is ready.
updateTshdEventsServerAddress: {
    path: '/teleport.lib.teleterm.v1.TerminalService/UpdateTshdEventsServerAddress',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.UpdateTshdEventsServerAddressRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.UpdateTshdEventsServerAddressResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_UpdateTshdEventsServerAddressResponse,
  },
  // ListRootClusters lists root clusters
// Does not include detailed cluster information that would require a network request.
listRootClusters: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ListRootClusters',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.ListClustersRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.ListClustersResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ListClustersRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ListClustersRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_ListClustersResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_ListClustersResponse,
  },
  // ListLeafClusters lists leaf clusters
// Does not include detailed cluster information that would require a network request.
listLeafClusters: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ListLeafClusters',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.ListLeafClustersRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.ListClustersResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ListLeafClustersRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ListLeafClustersRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_ListClustersResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_ListClustersResponse,
  },
  // GetDatabases returns a filtered and paginated list of databases
getDatabases: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetDatabases',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetDatabasesRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetDatabasesResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetDatabasesRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetDatabasesRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetDatabasesResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetDatabasesResponse,
  },
  // ListDatabaseUsers lists allowed users for the given database based on the role set.
listDatabaseUsers: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ListDatabaseUsers',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.ListDatabaseUsersRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.ListDatabaseUsersResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ListDatabaseUsersRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ListDatabaseUsersRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_ListDatabaseUsersResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_ListDatabaseUsersResponse,
  },
  // GetServers returns filtered, sorted, and paginated servers
getServers: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetServers',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetServersRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetServersResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetServersRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetServersRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetServersResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetServersResponse,
  },
  // GetAccessRequests lists filtered AccessRequests
getAccessRequests: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetAccessRequests',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetAccessRequestsRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetAccessRequestsResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetAccessRequestsRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetAccessRequestsRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetAccessRequestsResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetAccessRequestsResponse,
  },
  // GetAccessRequest retreives a single Access Request
getAccessRequest: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetAccessRequest',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetAccessRequestRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetAccessRequestResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetAccessRequestRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetAccessRequestRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetAccessRequestResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetAccessRequestResponse,
  },
  // DeleteAccessRequest deletes the access request by id
deleteAccessRequest: {
    path: '/teleport.lib.teleterm.v1.TerminalService/DeleteAccessRequest',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.DeleteAccessRequestRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_DeleteAccessRequestRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_DeleteAccessRequestRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // CreateAccessRequest creates an access request
createAccessRequest: {
    path: '/teleport.lib.teleterm.v1.TerminalService/CreateAccessRequest',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.CreateAccessRequestRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.CreateAccessRequestResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_CreateAccessRequestRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_CreateAccessRequestRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_CreateAccessRequestResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_CreateAccessRequestResponse,
  },
  // ReviewAccessRequest submits a review for an Access Request
reviewAccessRequest: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ReviewAccessRequest',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.ReviewAccessRequestRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.ReviewAccessRequestResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ReviewAccessRequestRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ReviewAccessRequestRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_ReviewAccessRequestResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_ReviewAccessRequestResponse,
  },
  // GetRequestableRoles gets all requestable roles
getRequestableRoles: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetRequestableRoles',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetRequestableRolesRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetRequestableRolesResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetRequestableRolesRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetRequestableRolesRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetRequestableRolesResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetRequestableRolesResponse,
  },
  // AssumeRole assumes the role of the given access request
assumeRole: {
    path: '/teleport.lib.teleterm.v1.TerminalService/AssumeRole',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.AssumeRoleRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_AssumeRoleRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_AssumeRoleRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // PromoteAccessRequest promotes an access request to an access list.
promoteAccessRequest: {
    path: '/teleport.lib.teleterm.v1.TerminalService/PromoteAccessRequest',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.PromoteAccessRequestRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.PromoteAccessRequestResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_PromoteAccessRequestRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_PromoteAccessRequestRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_PromoteAccessRequestResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_PromoteAccessRequestResponse,
  },
  // GetSuggestedAccessLists returns suggested access lists for an access request.
getSuggestedAccessLists: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetSuggestedAccessLists',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetSuggestedAccessListsRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetSuggestedAccessListsResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetSuggestedAccessListsResponse,
  },
  // GetKubes returns filtered, sorted, and paginated kubes
getKubes: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetKubes',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetKubesRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetKubesResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetKubesRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetKubesRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetKubesResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetKubesResponse,
  },
  // GetApps returns a filtered and paginated list of apps.
getApps: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetApps',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetAppsRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetAppsResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetAppsRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetAppsRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetAppsResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetAppsResponse,
  },
  // AddCluster adds a cluster to profile
addCluster: {
    path: '/teleport.lib.teleterm.v1.TerminalService/AddCluster',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.AddClusterRequest,
    responseType: teleport_lib_teleterm_v1_cluster_pb.Cluster,
    requestSerialize: serialize_teleport_lib_teleterm_v1_AddClusterRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_AddClusterRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_Cluster,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_Cluster,
  },
  // RemoveCluster removes a cluster from profile
removeCluster: {
    path: '/teleport.lib.teleterm.v1.TerminalService/RemoveCluster',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.RemoveClusterRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_RemoveClusterRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_RemoveClusterRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // ListGateways lists gateways
listGateways: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ListGateways',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.ListGatewaysRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.ListGatewaysResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ListGatewaysRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ListGatewaysRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_ListGatewaysResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_ListGatewaysResponse,
  },
  // CreateGateway creates a gateway
createGateway: {
    path: '/teleport.lib.teleterm.v1.TerminalService/CreateGateway',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.CreateGatewayRequest,
    responseType: teleport_lib_teleterm_v1_gateway_pb.Gateway,
    requestSerialize: serialize_teleport_lib_teleterm_v1_CreateGatewayRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_CreateGatewayRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_Gateway,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_Gateway,
  },
  // RemoveGateway removes a gateway
removeGateway: {
    path: '/teleport.lib.teleterm.v1.TerminalService/RemoveGateway',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.RemoveGatewayRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_RemoveGatewayRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_RemoveGatewayRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // SetGatewayTargetSubresourceName changes the TargetSubresourceName field of gateway.Gateway
// and returns the updated version of gateway.Gateway.
//
// In Connect this is used to update the db name of a db connection along with the CLI command.
setGatewayTargetSubresourceName: {
    path: '/teleport.lib.teleterm.v1.TerminalService/SetGatewayTargetSubresourceName',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.SetGatewayTargetSubresourceNameRequest,
    responseType: teleport_lib_teleterm_v1_gateway_pb.Gateway,
    requestSerialize: serialize_teleport_lib_teleterm_v1_SetGatewayTargetSubresourceNameRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_SetGatewayTargetSubresourceNameRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_Gateway,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_Gateway,
  },
  // SetGatewayLocalPort starts a new gateway on the new port, stops the old gateway and then
// assigns the URI of the old gateway to the new one. It does so without fetching a new db cert.
setGatewayLocalPort: {
    path: '/teleport.lib.teleterm.v1.TerminalService/SetGatewayLocalPort',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.SetGatewayLocalPortRequest,
    responseType: teleport_lib_teleterm_v1_gateway_pb.Gateway,
    requestSerialize: serialize_teleport_lib_teleterm_v1_SetGatewayLocalPortRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_SetGatewayLocalPortRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_Gateway,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_Gateway,
  },
  // GetAuthSettings returns cluster auth settigns
getAuthSettings: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetAuthSettings',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetAuthSettingsRequest,
    responseType: teleport_lib_teleterm_v1_auth_settings_pb.AuthSettings,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetAuthSettingsRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetAuthSettingsRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_AuthSettings,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_AuthSettings,
  },
  // GetCluster returns cluster. Makes a network request and includes detailed
// information about enterprise features availabed on the connected auth server
getCluster: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetCluster',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetClusterRequest,
    responseType: teleport_lib_teleterm_v1_cluster_pb.Cluster,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetClusterRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetClusterRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_Cluster,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_Cluster,
  },
  // Login logs in a user to a cluster
login: {
    path: '/teleport.lib.teleterm.v1.TerminalService/Login',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.LoginRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_LoginRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_LoginRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // LoginPasswordless logs in a user to a cluster passwordlessly.
//
// The RPC is streaming both ways and the message sequence example for hardware keys are:
// (-> means client-to-server, <- means server-to-client)
//
// Hardware keys:
// -> Init
// <- Send PasswordlessPrompt enum TAP to choose a device
// -> Receive TAP device response
// <- Send PasswordlessPrompt enum PIN
// -> Receive PIN response
// <- Send PasswordlessPrompt enum RETAP to confirm
// -> Receive RETAP device response
// <- Send list of credentials (e.g. usernames) associated with device
// -> Receive the index number associated with the selected credential in list
// <- End
loginPasswordless: {
    path: '/teleport.lib.teleterm.v1.TerminalService/LoginPasswordless',
    requestStream: true,
    responseStream: true,
    requestType: teleport_lib_teleterm_v1_service_pb.LoginPasswordlessRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.LoginPasswordlessResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_LoginPasswordlessRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_LoginPasswordlessRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_LoginPasswordlessResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_LoginPasswordlessResponse,
  },
  // ClusterLogin logs out a user from cluster
logout: {
    path: '/teleport.lib.teleterm.v1.TerminalService/Logout',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.LogoutRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_LogoutRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_LogoutRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // TransferFile sends a request to download/upload a file
transferFile: {
    path: '/teleport.lib.teleterm.v1.TerminalService/TransferFile',
    requestStream: false,
    responseStream: true,
    requestType: teleport_lib_teleterm_v1_service_pb.FileTransferRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.FileTransferProgress,
    requestSerialize: serialize_teleport_lib_teleterm_v1_FileTransferRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_FileTransferRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_FileTransferProgress,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_FileTransferProgress,
  },
  // ReportUsageEvent allows to send usage events that are then anonymized and forwarded to prehog
reportUsageEvent: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ReportUsageEvent',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_usage_events_pb.ReportUsageEventRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.EmptyResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ReportUsageEventRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ReportUsageEventRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_EmptyResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_EmptyResponse,
  },
  // UpdateHeadlessAuthenticationState updates a headless authentication resource's state.
// An MFA challenge will be prompted when approving a headless authentication.
updateHeadlessAuthenticationState: {
    path: '/teleport.lib.teleterm.v1.TerminalService/UpdateHeadlessAuthenticationState',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.UpdateHeadlessAuthenticationStateRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.UpdateHeadlessAuthenticationStateResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_UpdateHeadlessAuthenticationStateResponse,
  },
  // CreateConnectMyComputerRole creates a role which allows access to nodes with the label
// teleport.dev/connect-my-computer/owner: <cluster user> and allows logging in to those nodes as
// the current system user.
createConnectMyComputerRole: {
    path: '/teleport.lib.teleterm.v1.TerminalService/CreateConnectMyComputerRole',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerRoleRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerRoleResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerRoleResponse,
  },
  // CreateConnectMyComputerNodeToken creates a node join token that is valid for 5 minutes
createConnectMyComputerNodeToken: {
    path: '/teleport.lib.teleterm.v1.TerminalService/CreateConnectMyComputerNodeToken',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerNodeTokenRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.CreateConnectMyComputerNodeTokenResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_CreateConnectMyComputerNodeTokenResponse,
  },
  // DeleteConnectMyComputerToken deletes a join token
deleteConnectMyComputerToken: {
    path: '/teleport.lib.teleterm.v1.TerminalService/DeleteConnectMyComputerToken',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerTokenRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerTokenResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerTokenResponse,
  },
  // WaitForConnectMyComputerNodeJoin sets up a watcher and returns a response only after detecting
// that the Connect My Computer node for the particular cluster has joined the cluster (the
// OpPut event).
//
// This RPC times out by itself after a minute to prevent the request from hanging forever, in
// case the client didn't set a deadline or doesn't abort the request.
waitForConnectMyComputerNodeJoin: {
    path: '/teleport.lib.teleterm.v1.TerminalService/WaitForConnectMyComputerNodeJoin',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.WaitForConnectMyComputerNodeJoinRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.WaitForConnectMyComputerNodeJoinResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_WaitForConnectMyComputerNodeJoinResponse,
  },
  // DeleteConnectMyComputerNode deletes the Connect My Computer node.
deleteConnectMyComputerNode: {
    path: '/teleport.lib.teleterm.v1.TerminalService/DeleteConnectMyComputerNode',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerNodeRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.DeleteConnectMyComputerNodeResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_DeleteConnectMyComputerNodeResponse,
  },
  // GetConnectMyComputerNodeName reads the Connect My Computer node name (UUID) from a disk.
getConnectMyComputerNodeName: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetConnectMyComputerNodeName',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetConnectMyComputerNodeNameRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetConnectMyComputerNodeNameResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetConnectMyComputerNodeNameResponse,
  },
  // ListUnifiedResources retrieves a paginated list of all resource types displayable in the UI.
listUnifiedResources: {
    path: '/teleport.lib.teleterm.v1.TerminalService/ListUnifiedResources',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.ListUnifiedResourcesRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.ListUnifiedResourcesResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_ListUnifiedResourcesRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_ListUnifiedResourcesRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_ListUnifiedResourcesResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_ListUnifiedResourcesResponse,
  },
  // GetUserPreferences returns the combined (root + leaf cluster) preferences for a given user.
getUserPreferences: {
    path: '/teleport.lib.teleterm.v1.TerminalService/GetUserPreferences',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.GetUserPreferencesRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.GetUserPreferencesResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_GetUserPreferencesRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_GetUserPreferencesRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_GetUserPreferencesResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_GetUserPreferencesResponse,
  },
  // UpdateUserPreferences updates the preferences for a given user in appropriate root and leaf clusters.
// Only the properties that are set (cluster_preferences, unified_resource_preferences) will be updated.
updateUserPreferences: {
    path: '/teleport.lib.teleterm.v1.TerminalService/UpdateUserPreferences',
    requestStream: false,
    responseStream: false,
    requestType: teleport_lib_teleterm_v1_service_pb.UpdateUserPreferencesRequest,
    responseType: teleport_lib_teleterm_v1_service_pb.UpdateUserPreferencesResponse,
    requestSerialize: serialize_teleport_lib_teleterm_v1_UpdateUserPreferencesRequest,
    requestDeserialize: deserialize_teleport_lib_teleterm_v1_UpdateUserPreferencesRequest,
    responseSerialize: serialize_teleport_lib_teleterm_v1_UpdateUserPreferencesResponse,
    responseDeserialize: deserialize_teleport_lib_teleterm_v1_UpdateUserPreferencesResponse,
  },
};

exports.TerminalServiceClient = grpc.makeGenericClientConstructor(TerminalServiceService);
