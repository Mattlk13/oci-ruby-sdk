# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20180222
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The properties that configure OIDC token authentication in kube-apiserver.
  # For more information, see [Configuring the API Server](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-flags).
  #
  class ContainerEngine::Models::OpenIdConnectTokenAuthenticationConfig
    # URL of the provider that allows the API server to discover public signing keys.
    # Only URLs that use the https:// scheme are accepted. This is typically the provider's discovery URL,
    # changed to have an empty path.
    #
    # @return [String]
    attr_accessor :issuer_url

    # A client id that all tokens must be issued for.
    #
    # @return [String]
    attr_accessor :client_id

    # JWT claim to use as the user name. By default sub, which is expected to be a unique identifier of the end
    # user. Admins can choose other claims, such as email or name, depending on their provider. However, claims
    # other than email will be prefixed with the issuer URL to prevent naming clashes with other plugins.
    #
    # @return [String]
    attr_accessor :username_claim

    # Prefix prepended to username claims to prevent clashes with existing names (such as system:users).
    # For example, the value oidc: will create usernames like oidc:jane.doe. If this flag isn't provided and
    # --oidc-username-claim is a value other than email the prefix defaults to ( Issuer URL )# where
    # ( Issuer URL ) is the value of --oidc-issuer-url. The value - can be used to disable all prefixing.
    #
    # @return [String]
    attr_accessor :username_prefix

    # JWT claim to use as the user's group. If the claim is present it must be an array of strings.
    #
    # @return [String]
    attr_accessor :groups_claim

    # Prefix prepended to group claims to prevent clashes with existing names (such as system:groups).
    #
    # @return [String]
    attr_accessor :groups_prefix

    # A key=value pair that describes a required claim in the ID Token. If set, the claim is verified to be present
    # in the ID Token with a matching value. Repeat this flag to specify multiple claims.
    #
    # @return [Array<OCI::ContainerEngine::Models::KeyValue>]
    attr_accessor :required_claims

    # A Base64 encoded public RSA or ECDSA certificates used to signed your identity provider's web certificate.
    #
    # @return [String]
    attr_accessor :ca_certificate

    # The signing algorithms accepted. Default is [\"RS256\"].
    #
    # @return [Array<String>]
    attr_accessor :signing_algorithms

    # **[Required]** Whether the cluster has OIDC Auth Config enabled. Defaults to false.
    #
    # @return [BOOLEAN]
    attr_accessor :is_open_id_connect_auth_enabled

    # A Base64 encoded string of a Kubernetes OIDC Auth Config file. More info [here](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
    #
    # @return [String]
    attr_accessor :configuration_file

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'issuer_url': :'issuerUrl',
        'client_id': :'clientId',
        'username_claim': :'usernameClaim',
        'username_prefix': :'usernamePrefix',
        'groups_claim': :'groupsClaim',
        'groups_prefix': :'groupsPrefix',
        'required_claims': :'requiredClaims',
        'ca_certificate': :'caCertificate',
        'signing_algorithms': :'signingAlgorithms',
        'is_open_id_connect_auth_enabled': :'isOpenIdConnectAuthEnabled',
        'configuration_file': :'configurationFile'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'issuer_url': :'String',
        'client_id': :'String',
        'username_claim': :'String',
        'username_prefix': :'String',
        'groups_claim': :'String',
        'groups_prefix': :'String',
        'required_claims': :'Array<OCI::ContainerEngine::Models::KeyValue>',
        'ca_certificate': :'String',
        'signing_algorithms': :'Array<String>',
        'is_open_id_connect_auth_enabled': :'BOOLEAN',
        'configuration_file': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :issuer_url The value to assign to the {#issuer_url} property
    # @option attributes [String] :client_id The value to assign to the {#client_id} property
    # @option attributes [String] :username_claim The value to assign to the {#username_claim} property
    # @option attributes [String] :username_prefix The value to assign to the {#username_prefix} property
    # @option attributes [String] :groups_claim The value to assign to the {#groups_claim} property
    # @option attributes [String] :groups_prefix The value to assign to the {#groups_prefix} property
    # @option attributes [Array<OCI::ContainerEngine::Models::KeyValue>] :required_claims The value to assign to the {#required_claims} property
    # @option attributes [String] :ca_certificate The value to assign to the {#ca_certificate} property
    # @option attributes [Array<String>] :signing_algorithms The value to assign to the {#signing_algorithms} property
    # @option attributes [BOOLEAN] :is_open_id_connect_auth_enabled The value to assign to the {#is_open_id_connect_auth_enabled} property
    # @option attributes [String] :configuration_file The value to assign to the {#configuration_file} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.issuer_url = attributes[:'issuerUrl'] if attributes[:'issuerUrl']

      raise 'You cannot provide both :issuerUrl and :issuer_url' if attributes.key?(:'issuerUrl') && attributes.key?(:'issuer_url')

      self.issuer_url = attributes[:'issuer_url'] if attributes[:'issuer_url']

      self.client_id = attributes[:'clientId'] if attributes[:'clientId']

      raise 'You cannot provide both :clientId and :client_id' if attributes.key?(:'clientId') && attributes.key?(:'client_id')

      self.client_id = attributes[:'client_id'] if attributes[:'client_id']

      self.username_claim = attributes[:'usernameClaim'] if attributes[:'usernameClaim']

      raise 'You cannot provide both :usernameClaim and :username_claim' if attributes.key?(:'usernameClaim') && attributes.key?(:'username_claim')

      self.username_claim = attributes[:'username_claim'] if attributes[:'username_claim']

      self.username_prefix = attributes[:'usernamePrefix'] if attributes[:'usernamePrefix']

      raise 'You cannot provide both :usernamePrefix and :username_prefix' if attributes.key?(:'usernamePrefix') && attributes.key?(:'username_prefix')

      self.username_prefix = attributes[:'username_prefix'] if attributes[:'username_prefix']

      self.groups_claim = attributes[:'groupsClaim'] if attributes[:'groupsClaim']

      raise 'You cannot provide both :groupsClaim and :groups_claim' if attributes.key?(:'groupsClaim') && attributes.key?(:'groups_claim')

      self.groups_claim = attributes[:'groups_claim'] if attributes[:'groups_claim']

      self.groups_prefix = attributes[:'groupsPrefix'] if attributes[:'groupsPrefix']

      raise 'You cannot provide both :groupsPrefix and :groups_prefix' if attributes.key?(:'groupsPrefix') && attributes.key?(:'groups_prefix')

      self.groups_prefix = attributes[:'groups_prefix'] if attributes[:'groups_prefix']

      self.required_claims = attributes[:'requiredClaims'] if attributes[:'requiredClaims']

      raise 'You cannot provide both :requiredClaims and :required_claims' if attributes.key?(:'requiredClaims') && attributes.key?(:'required_claims')

      self.required_claims = attributes[:'required_claims'] if attributes[:'required_claims']

      self.ca_certificate = attributes[:'caCertificate'] if attributes[:'caCertificate']

      raise 'You cannot provide both :caCertificate and :ca_certificate' if attributes.key?(:'caCertificate') && attributes.key?(:'ca_certificate')

      self.ca_certificate = attributes[:'ca_certificate'] if attributes[:'ca_certificate']

      self.signing_algorithms = attributes[:'signingAlgorithms'] if attributes[:'signingAlgorithms']

      raise 'You cannot provide both :signingAlgorithms and :signing_algorithms' if attributes.key?(:'signingAlgorithms') && attributes.key?(:'signing_algorithms')

      self.signing_algorithms = attributes[:'signing_algorithms'] if attributes[:'signing_algorithms']

      self.is_open_id_connect_auth_enabled = attributes[:'isOpenIdConnectAuthEnabled'] unless attributes[:'isOpenIdConnectAuthEnabled'].nil?
      self.is_open_id_connect_auth_enabled = false if is_open_id_connect_auth_enabled.nil? && !attributes.key?(:'isOpenIdConnectAuthEnabled') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :isOpenIdConnectAuthEnabled and :is_open_id_connect_auth_enabled' if attributes.key?(:'isOpenIdConnectAuthEnabled') && attributes.key?(:'is_open_id_connect_auth_enabled')

      self.is_open_id_connect_auth_enabled = attributes[:'is_open_id_connect_auth_enabled'] unless attributes[:'is_open_id_connect_auth_enabled'].nil?
      self.is_open_id_connect_auth_enabled = false if is_open_id_connect_auth_enabled.nil? && !attributes.key?(:'isOpenIdConnectAuthEnabled') && !attributes.key?(:'is_open_id_connect_auth_enabled') # rubocop:disable Style/StringLiterals

      self.configuration_file = attributes[:'configurationFile'] if attributes[:'configurationFile']

      raise 'You cannot provide both :configurationFile and :configuration_file' if attributes.key?(:'configurationFile') && attributes.key?(:'configuration_file')

      self.configuration_file = attributes[:'configuration_file'] if attributes[:'configuration_file']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        issuer_url == other.issuer_url &&
        client_id == other.client_id &&
        username_claim == other.username_claim &&
        username_prefix == other.username_prefix &&
        groups_claim == other.groups_claim &&
        groups_prefix == other.groups_prefix &&
        required_claims == other.required_claims &&
        ca_certificate == other.ca_certificate &&
        signing_algorithms == other.signing_algorithms &&
        is_open_id_connect_auth_enabled == other.is_open_id_connect_auth_enabled &&
        configuration_file == other.configuration_file
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines

    # @see the `==` method
    # @param [Object] other the other object to be compared
    def eql?(other)
      self == other
    end

    # rubocop:disable Metrics/AbcSize, Layout/EmptyLines


    # Calculates hash code according to all attributes.
    # @return [Fixnum] Hash code
    def hash
      [issuer_url, client_id, username_claim, username_prefix, groups_claim, groups_prefix, required_claims, ca_certificate, signing_algorithms, is_open_id_connect_auth_enabled, configuration_file].hash
    end
    # rubocop:enable Metrics/AbcSize, Layout/EmptyLines

    # rubocop:disable Metrics/AbcSize, Layout/EmptyLines


    # Builds the object from hash
    # @param [Hash] attributes Model attributes in the form of hash
    # @return [Object] Returns the model itself
    def build_from_hash(attributes)
      return nil unless attributes.is_a?(Hash)

      self.class.swagger_types.each_pair do |key, type|
        if type =~ /^Array<(.*)>/i
          # check to ensure the input is an array given that the the attribute
          # is documented as an array but the input is not
          if attributes[self.class.attribute_map[key]].is_a?(Array)
            public_method("#{key}=").call(
              attributes[self.class.attribute_map[key]]
                .map { |v| OCI::Internal::Util.convert_to_type(Regexp.last_match(1), v) }
            )
          end
        elsif !attributes[self.class.attribute_map[key]].nil?
          public_method("#{key}=").call(
            OCI::Internal::Util.convert_to_type(type, attributes[self.class.attribute_map[key]])
          )
        end
        # or else data not found in attributes(hash), not an issue as the data can be optional
      end

      self
    end
    # rubocop:enable Metrics/AbcSize, Layout/EmptyLines

    # Returns the string representation of the object
    # @return [String] String presentation of the object
    def to_s
      to_hash.to_s
    end

    # Returns the object in the form of hash
    # @return [Hash] Returns the object in the form of hash
    def to_hash
      hash = {}
      self.class.attribute_map.each_pair do |attr, param|
        value = public_method(attr).call
        next if value.nil? && !instance_variable_defined?("@#{attr}")

        hash[param] = _to_hash(value)
      end
      hash
    end

    private

    # Outputs non-array value in the form of hash
    # For object, use to_hash. Otherwise, just return the value
    # @param [Object] value Any valid value
    # @return [Hash] Returns the value in the form of hash
    def _to_hash(value)
      if value.is_a?(Array)
        value.compact.map { |v| _to_hash(v) }
      elsif value.is_a?(Hash)
        {}.tap do |hash|
          value.each { |k, v| hash[k] = _to_hash(v) }
        end
      elsif value.respond_to? :to_hash
        value.to_hash
      else
        value
      end
    end
  end
end
# rubocop:enable Lint/UnneededCopDisableDirective, Metrics/LineLength
