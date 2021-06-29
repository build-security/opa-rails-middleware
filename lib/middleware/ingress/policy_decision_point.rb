# frozen_string_literal: true

require 'json'
require 'faraday'
require 'openssl'
require 'base64'

require 'aws-sdk-ec2'
require 'aws-sdk-iam'

module BuildSecurity
    module Ingress
        ##
        # Ingress middleware that connects to a PDP to request authz decisions.
        class PolicyDecisionPoint

            ##
            # Initializes the PolicyDecisionPoint middleware.
            #
            # @param port [Integer] The port at which the PDP serves authz decisions.
            # @param hostname [String] The host at which the PDP serves authz decisions.
            # @param policy_path [String] The full path to policy (including package and rule) that makes the authz decision.
            # @param read_timeout_milliseconds [Integer] Timeout for reading packets from server.
            # @param connection_timeout_milliseconds [Integer] Timeout for establishing connection to server.
            # @param retry_max_attempts [Integer] Number of retries to server before giving up.
            # @param retry_backoff_milliseconds [Integer] Initial wait time before retry, doubles for every retry.
            def initialize(app,
                port: 8181,
                hostname: 'http://localhost', 
                policy_path: '/authz/allow',
                read_timeout_milliseconds: 5000,
                connection_timeout_milliseconds: 5000,
                retry_max_attempts: 2,
                retry_backoff_milliseconds: 250)

                @port = port
                @hostname = hostname
                @policy_path = policy_path
                @read_timeout_milliseconds = read_timeout_milliseconds
                @connection_timeout_milliseconds = connection_timeout_milliseconds
                @retry_max_attempts = 2
                @retry_backoff_milliseconds = retry_backoff_milliseconds

                @pdp_endpoint = endpoint()

                @client = Faraday.new(
                    url: @pdp_endpoint,
                    request: {
                        read_timeout: @read_timeout_milliseconds,
                        open_timeout: @connection_timeout_milliseconds,
                    }
                ) do |conn|
                    conn.request(:retry, max:2, interval: @retry_backoff_milliseconds/1000, backoff_factor: 2)
                end

                fetch_aws_parameters()
                update_aws_clients()
                
                @app = app
            end

            ##
            # Fetches current AWS region from AWS IMDS
            #
            # @return region [String]
            def fetch_aws_parameters
                ec2_metadata = Aws::EC2Metadata.new
                mdoc = JSON.parse(ec2_metadata.get('/latest/dynamic/instance-identity/document'))
                @aws_region = mdoc['region']
                
                idoc = JSON.parse(ec2_metadata.get('/latest/meta-data/iam/info'))
                @aws_iam_instance_profile_name = idoc['InstanceProfileArn'].split('/')[-1]

                cdoc = JSON.parse(ec2_metadata.get("/latest/meta-data/iam/security-credentials/#{@aws_iam_instance_profile_name}"))
                @aws_access_key_id = cdoc['AccessKeyId']
                @aws_secret_access_key = cdoc['SecretAccessKey']
                @aws_session_token = cdoc['Token']
            end

            ##
            # Creates/updates AWS clients
            def update_aws_clients(region = nil)
                if region.nil? || region != @aws_region
                    unless region.nil?
                        @aws_region = region
                    end

                    @ec2 = Aws::EC2::Client.new(
                        region: @aws_region,
                        credentials: Aws::Credentials.new(@aws_access_key_id, @aws_secret_access_key, @aws_session_token)
                    )
                    @iam = Aws::IAM::Client.new(
                        region: @aws_region,
                        credentials: Aws::Credentials.new(@aws_access_key_id, @aws_secret_access_key, @aws_session_token)
                    )
                end
            end

            ##
            # Invoked for incoming requests; calls the PDP with request context to make decision.
            #
            # @raise [Middleware::Ingress::AuthzError] if the request fails authorization.
            def call(env)
                headers = ActionDispatch::Http::Headers.from_hash(env)

                signed_data = Base64.urlsafe_decode64(headers['HTTP_AWS_SIGNED_METADATA'])
                certificate = File.read(File.join(File.dirname(__FILE__), 'aws_imds_cert.pem'))

                metadata = verify(signed_data, certificate)
                update_aws_clients(metadata['region'])
                iam_instance_profile = get_instance_profile(metadata['instanceId'])

                body = input(env, headers, metadata, iam_instance_profile).to_json

                response = @client.post('', body, 'Content-Type' => 'application/json')

                if not response.success?
                    raise AuthzError.new(
                        StandardError.new("Unexpected response #{response.status} from decision endpoint #{@pdp_endpoint}")
                    )
                end

                if JSON.parse(response.body).with_indifferent_access['result'] != true
                    raise AuthzError.new(
                        StandardError.new("Request was not authorized by decision endpoint #{@pdp_endpoint}")
                    )
                end

            rescue Faraday::Error => error
                raise AuthzError.new(error)
            else
                # If no exception is raised, pass the request to the next middleware.
                @app.call(env)
            end

            ##
            # Constructs the endpoint to which PDP authz requests are sent.
            #
            # @return [String] the endpoint
            def endpoint
                if not @hostname.include? '://'
                    @hostname = 'http://' + @hostname
                end

                @hostname = @hostname.delete_suffix('/')

                if @port.respond_to?(:to_s)
                    @port = @port.to_s
                end

                if not @port.start_with?(':')
                    @port = ':' + @port
                end

                if not @policy_path.start_with?('/')
                    @policy_path = '/' + @policy_path
                end

                @hostname + @port + '/v1/data' + @policy_path
            end

            ##
            # Verifies PKCS7 signed data
            #
            # @param pkcs7_signed_data [String] PKCS7 signed data structure with attached data
            # @param certificate [String] certificate provided by signer
            # 
            # @return data [Hash] content from the PKCS7 signed data structure
            def verify(pkcs7_signed_data, certificate)
                cert = OpenSSL::X509::Certificate.new(certificate)
                pkcs7 = OpenSSL::PKCS7.new(pkcs7_signed_data)
                store = OpenSSL::X509::Store.new()
                
                unless pkcs7.verify([cert], store, pkcs7.data, OpenSSL::PKCS7::NOVERIFY)
                    raise AuthnError(
                        StandardError.new("Could not verify incoming request signature")
                    )
                end

                JSON.parse(pkcs7.data)
            end

            ##
            # Fetches IAM Instace Profile information associated with the EC2 instance.
            #
            # @param ec2_instance_id [String]
            #
            # @return instance_profile [Hash] details of IAM Instance Profile associated with EC2 instance, or nil
            def get_instance_profile(ec2_instance_id)
                instances =  @ec2.describe_instances({instance_ids: [ec2_instance_id]})
                ec2_instance_profile = instances.reservations[0].instances[0].iam_instance_profile

                unless ec2_instance_profile.nil?
                    instance_profile_name = ec2_instance_profile.arn.split('/')[-1]
                    return @iam.get_instance_profile({
                        instance_profile_name: instance_profile_name,
                    }).to_h[:instance_profile]
                end

                nil
            end

            ##
            # Constructs the request context required to make authz decision, which is sent to the PDP.
            # Header values received in the request are normalized. See NOTE below for examples.
            #
            # @return [Hash] the request context
            def input(env, headers, metadata, iam_instance_profile)
                req = Rack::Request.new(env)

                {
                    'input': {
                        'request': {
                            'scheme': req.scheme,
                            'method': req.request_method,
                            'path': req.path,
                            'query':  Rack::Utils.parse_nested_query(req.query_string),

                            # NOTE: Rack normalizes all headers by adding prefixes, making uppercase and using underscores.
                            # Examples
                            #   Content-Type -> CONTENT_TYPE
                            #   Accept -> HTTP_ACCEPT
                            #   Custom-Header -> HTTP_CUSTOM_HEADER
                            #
                            # To separate these request headers from other environment headers added by Rails/Rack,
                            # the following prefix matching is performed.
                            'headers': headers.to_h.select { |k,v|
                                ['HTTP','CONTENT','AUTHORIZATION'].any? { |s| k.to_s.starts_with? s }
                            },
                        },
                        'source': {
                            'ipAddress': req.host,
                            'port': req.port,
                        },
                        'destination': {
                            'ipAddress': req.server_name,
                            'port': req.server_port,
                        },
                        'aws': {
                            'imds': metadata,
                            'iam_instance_profile': iam_instance_profile,
                        }
                    }
                }
            end
        end

        ##
        # Represents an authentication attempt failure.
        class AuthnError < StandardError
            def initialize(e = nil)
                super e
                set_backtrace e.backtrace if e
            end
        end

        ##
        # Represents an authorization attempt failure.
        class AuthzError < StandardError
            def initialize(e = nil)
                super e
                set_backtrace e.backtrace if e
            end
        end
    end
end
