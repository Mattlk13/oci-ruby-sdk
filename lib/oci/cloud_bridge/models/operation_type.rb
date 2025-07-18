# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220509

module OCI
  module CloudBridge::Models
    OPERATION_TYPE_ENUM = [
      OPERATION_TYPE_CREATE_ENVIRONMENT = 'CREATE_ENVIRONMENT'.freeze,
      OPERATION_TYPE_UPDATE_ENVIRONMENT = 'UPDATE_ENVIRONMENT'.freeze,
      OPERATION_TYPE_DELETE_ENVIRONMENT = 'DELETE_ENVIRONMENT'.freeze,
      OPERATION_TYPE_MOVE_ENVIRONMENT = 'MOVE_ENVIRONMENT'.freeze,
      OPERATION_TYPE_CREATE_OCB_AGENT = 'CREATE_OCB_AGENT'.freeze,
      OPERATION_TYPE_UPDATE_OCB_AGENT = 'UPDATE_OCB_AGENT'.freeze,
      OPERATION_TYPE_DELETE_OCB_AGENT = 'DELETE_OCB_AGENT'.freeze,
      OPERATION_TYPE_MOVE_OCB_AGENT = 'MOVE_OCB_AGENT'.freeze,
      OPERATION_TYPE_CREATE_AGENT_DEPENDENCY = 'CREATE_AGENT_DEPENDENCY'.freeze,
      OPERATION_TYPE_UPDATE_AGENT_DEPENDENCY = 'UPDATE_AGENT_DEPENDENCY'.freeze,
      OPERATION_TYPE_DELETE_AGENT_DEPENDENCY = 'DELETE_AGENT_DEPENDENCY'.freeze,
      OPERATION_TYPE_MOVE_AGENT_DEPENDENCY = 'MOVE_AGENT_DEPENDENCY'.freeze,
      OPERATION_TYPE_CREATE_INVENTORY = 'CREATE_INVENTORY'.freeze,
      OPERATION_TYPE_DELETE_INVENTORY = 'DELETE_INVENTORY'.freeze,
      OPERATION_TYPE_IMPORT_INVENTORY = 'IMPORT_INVENTORY'.freeze,
      OPERATION_TYPE_DELETE_ASSET_SOURCE = 'DELETE_ASSET_SOURCE'.freeze,
      OPERATION_TYPE_REFRESH_ASSET_SOURCE = 'REFRESH_ASSET_SOURCE'.freeze,
      OPERATION_TYPE_CREATE_ASSET_SOURCE = 'CREATE_ASSET_SOURCE'.freeze,
      OPERATION_TYPE_UPDATE_ASSET_SOURCE = 'UPDATE_ASSET_SOURCE'.freeze,
      OPERATION_TYPE_UPDATE_PLUGIN_STATE = 'UPDATE_PLUGIN_STATE'.freeze,
      OPERATION_TYPE_CLOUD_AWS_DISCOVERY = 'CLOUD_AWS_DISCOVERY'.freeze,
      OPERATION_TYPE_COLLECT_AWS_REALTIME_METRICS = 'COLLECT_AWS_REALTIME_METRICS'.freeze,
      OPERATION_TYPE_COLLECT_AWS_HISTORICAL_METRICS = 'COLLECT_AWS_HISTORICAL_METRICS'.freeze
    ].freeze
  end
end
