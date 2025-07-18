# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20180222

module OCI
  module ContainerEngine::Models
    WORK_REQUEST_OPERATION_TYPE_ENUM = [
      WORK_REQUEST_OPERATION_TYPE_CLUSTER_CREATE = 'CLUSTER_CREATE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_CLUSTER_UPDATE = 'CLUSTER_UPDATE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_CLUSTER_DELETE = 'CLUSTER_DELETE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_CREATE_NAMESPACE = 'CREATE_NAMESPACE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_NODEPOOL_CREATE = 'NODEPOOL_CREATE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_NODEPOOL_UPDATE = 'NODEPOOL_UPDATE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_NODEPOOL_DELETE = 'NODEPOOL_DELETE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_NODEPOOL_RECONCILE = 'NODEPOOL_RECONCILE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_NODEPOOL_CYCLING = 'NODEPOOL_CYCLING'.freeze,
      WORK_REQUEST_OPERATION_TYPE_WORKREQUEST_CANCEL = 'WORKREQUEST_CANCEL'.freeze,
      WORK_REQUEST_OPERATION_TYPE_VIRTUALNODEPOOL_CREATE = 'VIRTUALNODEPOOL_CREATE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_VIRTUALNODEPOOL_UPDATE = 'VIRTUALNODEPOOL_UPDATE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_VIRTUALNODEPOOL_DELETE = 'VIRTUALNODEPOOL_DELETE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_VIRTUALNODE_DELETE = 'VIRTUALNODE_DELETE'.freeze,
      WORK_REQUEST_OPERATION_TYPE_ENABLE_ADDON = 'ENABLE_ADDON'.freeze,
      WORK_REQUEST_OPERATION_TYPE_UPDATE_ADDON = 'UPDATE_ADDON'.freeze,
      WORK_REQUEST_OPERATION_TYPE_DISABLE_ADDON = 'DISABLE_ADDON'.freeze,
      WORK_REQUEST_OPERATION_TYPE_RECONCILE_ADDON = 'RECONCILE_ADDON'.freeze,
      WORK_REQUEST_OPERATION_TYPE_CLUSTER_NODE_REBOOT = 'CLUSTER_NODE_REBOOT'.freeze,
      WORK_REQUEST_OPERATION_TYPE_CLUSTER_NODE_REPLACE_BOOT_VOLUME = 'CLUSTER_NODE_REPLACE_BOOT_VOLUME'.freeze
    ].freeze
  end
end
