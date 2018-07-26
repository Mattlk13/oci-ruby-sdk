# Copyright (c) 2016, 2018, Oracle and/or its affiliates. All rights reserved.

require 'json'
require 'net/http'
require 'thread'

require 'oci/auth/internal/auth_token_request_signer'
require 'oci/auth/session_key_supplier'

module OCI
  module Auth
    # A client which can be used to retrieve a token from Auth Service. It needs the following supplied to it:
    #
    #   * The endpoint for Auth Service
    #   * Our tenancy OCID
    #   * A session key supplier so that we can send its public key as part of the token request. The private key in the session key supplier should be used to sign all requests made with the token
    #   * The certificate (via leaf_certificate_supplier) which will be used to sign the requests to Auth Service.
    #
    # Optionally, intermediate certificates (if present) can be supplied as part of the request to Auth Service.
    #
    # The client has knowledge of its last requested token and can re-request the token if it is expired (otherwise
    # it will vend the last requested token if it is not expired).
    class FederationClient
      # A supplier which vends a private and public key for signing token requests to Auth Service.
      # The public key will be sent as part of the token request and the private key should be used to
      # sign all requests made with the token vended by this client
      # @return [OCI::Auth::SessionKeySupplier] A supplier which vends a private and public key for signing token requests to Auth Service
      attr_reader :session_key_supplier

      # Creates a new FederationClient
      #
      # @param [String] federation_endpoint The Auth Service endpoint from which to retrieve the token
      # @param [String] tenancy_id The OCID of the tenancy whose resources will be interacted with by users of the token
      # @param [OCI::Auth::SessionKeySupplier] session_key_supplier A supplier which vends a private and public key for signing token requests to Auth Service
      # @param [OCI::Auth::UrlBasedCertificateRetriever] leaf_certificate_supplier The certificate which will be used to sign requests to Auth Service
      # @param [Array<OCI::Auth::UrlBasedCertificateRetriever>] intermediate_certificate_suppliers An array of retrievers which can be used to fetch intermediate certificates which can be sent as part of the Auth Service request. If not provided, defaults to an empty array
      # @param [String] cert_bundle_path The full file path to a custom certificate bundle which can be used for SSL verification against the Auth Service endpoint. If not provided (e.g. because a custom bundle is not needed), defaults to nil
      def initialize(federation_endpoint, tenancy_id, session_key_supplier, leaf_certificate_supplier, intermediate_certificate_suppliers: [], cert_bundle_path: nil)
        @federation_endpoint = federation_endpoint
        uri = URI(@federation_endpoint)
        @federation_http_client = Net::HTTP.new(uri.hostname, uri.port)
        @federation_http_client.use_ssl = (uri.scheme == 'https')
        @federation_http_client.ca_file = cert_bundle_path if cert_bundle_path

        @tenancy_id = tenancy_id
        @session_key_supplier = session_key_supplier
        @leaf_certificate_supplier = leaf_certificate_supplier
        @intermediate_certificate_suppliers = intermediate_certificate_suppliers

        @refresh_lock = Mutex.new
        @security_token = nil
      end

      # Retrieves a security token, but always asks Auth Service for a new token, regardless of whether or not the previously requested
      # token is still valid
      # @return [String] The security token
      def security_token!
        refresh_security_token_inner
      end

      # Retrieves the security token held by the client. If the previously retrieved token is still valid, it is vended
      # rather than making another request
      # @return [String] The security token
      def security_token
        return @security_token.security_token if @security_token && @security_token.token_valid?
        refresh_security_token_inner
      end

      private
        def refresh_security_token_inner
          @refresh_lock.lock

          @session_key_supplier.refresh
          @leaf_certificate_supplier.refresh

          updated_tenancy_id = OCI::Auth::Util.get_tenancy_id_from_certificate(@leaf_certificate_supplier.certificate)
          raise "Unexpected update of tenancy OCID in the leaf certificate. Previous tenancy: #{@tenancy_id}, Updated: #{updated_tenancy_id}" if updated_tenancy_id != @tenancy_id

          @intermediate_certificate_suppliers.each { |supplier| supplier.refresh }

          leaf_certificate_pem = @leaf_certificate_supplier.certificate_pem
          request_payload = {
            'certificate': OCI::Auth::Util.sanitize_certificate_string(leaf_certificate_pem),
            'publicKey': OCI::Auth::Util.sanitize_certificate_string(@session_key_supplier.key_pair[:public_key].to_pem)
          }

          unless @intermediate_certificate_suppliers.empty?
            retrieved_certs = []
            @intermediate_certificate_suppliers.each { |supplier| retrieved_certs << OCI::Auth::Util.sanitize_certificate_string(supplier.certificate_pem) }
            request_payload['intermediateCertificates'] = retrieved_certs
          end

          fingerprint = OCI::Auth::Util.colon_separate_fingerprint(OpenSSL::Digest::SHA1.new(@leaf_certificate_supplier.certificate.to_der).to_s)
          signer = OCI::Auth::Internal::AuthTokenRequestSigner.new(@tenancy_id, fingerprint, @leaf_certificate_supplier.private_key_pem)

          request = Net::HTTP::Post.new(@federation_endpoint)
          request.body = request_payload.to_json

          header_params = {}
          header_params['content-type'] = 'application/json'
          signer.sign(:post, @federation_endpoint, header_params, request.body)
          header_params.each { |key, value| request[key.to_s] = value }

          raw_body = nil
          @federation_http_client.start do
            @federation_http_client.request(request) do |response|
              raw_body = response.body
            end
          end

          begin
            parsed_response = JSON.parse(raw_body)
            raise "No token received in the response from auth service: #{raw_body}" unless parsed_response.has_key?('token')

            @security_token = OCI::Auth::SecurityTokenContainer.new(parsed_response['token'])
          rescue JSON::ParserError => e
            raise "Unable to parse response from Auth Service: #{raw_body}"
          end

          @security_token.security_token
        ensure
          @refresh_lock.unlock if @refresh_lock.locked? && @refresh_lock.owned?
        end
    end
  end
end
