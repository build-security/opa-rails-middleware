# frozen_string_literal: true

require "json"

module PolicyDecisionPoint
  ##
  # Ingress middleware that connects to a PDP to request authz decisions.
  class PDP

    @@DEFAULT_PORT = 8181
    @@DEFAULT_HOSTNAME = "http://localhost"
    @@DEFAULT_POLICY_PATH = "/authz/allow"
    @@DEFAULT_READ_TIMEOUT_MILLISECONDS = 5000
    @@DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS = 5000
    @@DEFAULT_RETRY_MAX_ATTEMPTS = 2
    @@DEFAULT_RETRY_BACKOFF_MILLISECONDS = 250

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
        port: @@DEFAULT_PORT,
        hostname: @@DEFAULT_HOSTNAME,
        policy_path: @@DEFAULT_POLICY_PATH,
        read_timeout_milliseconds: @@DEFAULT_READ_TIMEOUT_MILLISECONDS,
        connection_timeout_milliseconds: @@DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS,
        retry_max_attempts: @@DEFAULT_RETRY_MAX_ATTEMPTS,
        retry_backoff_milliseconds: @@DEFAULT_RETRY_BACKOFF_MILLISECONDS)

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
          conn.request(:retry, max: 2, interval: @retry_backoff_milliseconds / 1000, backoff_factor: 2)
        end

        @app = app
    end

    ##
    # Invoked for incoming requests; calls the PDP with request context to make decision.
    #
    # @raise [Middleware::Ingress::AuthzError] if the request fails authorization.
    def call(env)
      body = input(env).to_json

      response = @client.post("", body, "Content-Type" => "application/json")

      if not response.success?
        raise AuthzError.new(
            StandardError.new("Unexpected response #{response.status} from decision endpoint #{@pdp_endpoint}")
        )
      end

      if JSON.parse(response.body).with_indifferent_access["result"] != true
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
      if not @hostname.include? "://"
        @hostname = "http://" + @hostname
      end

        @hostname = @hostname.delete_suffix("/")

        if @port.respond_to?(:to_s)
          @port = @port.to_s
        end

        if not @port.start_with?(":")
          @port = ":" + @port
        end

        if not @policy_path.start_with?("/")
          @policy_path = "/" + @policy_path
        end

        @hostname + @port + "/v1/data" + @policy_path
    end

    ##
    # Constructs the request context required to make authz decision, which is sent to the PDP.
    # Header values received in the request are normalized. See NOTE below for examples.
    #
    # @return [Hash] the request context
    def input(env)
      req = Rack::Request.new(env)
        headers = ActionDispatch::Http::Headers.from_hash(env)

        {
            'input': {
                'request': {
                    'scheme': req.scheme,
                    'method': req.request_method,
                    'path': req.path,
                    'query': Rack::Utils.parse_nested_query(req.query_string),

                    # NOTE: Rack normalizes all headers by adding prefixes, making uppercase and using underscores.
                    # Examples
                    #   Content-Type -> CONTENT_TYPE
                    #   Accept -> HTTP_ACCEPT
                    #   Custom-Header -> HTTP_CUSTOM_HEADER
                    #
                    # To separate these request headers from other environment headers added by Rails/Rack,
                    # the following prefix matching is performed.
                    'headers': headers.to_h.select { |k, v|
                      ["HTTP", "CONTENT", "AUTHORIZATION"].any? { |s| k.to_s.starts_with? s }
                    },
                },
                'source': {
                    'ipAddress': req.host,
                    'port': req.port,
                },
                'destination': {
                    'ipAddress': req.server_name,
                    'port': req.server_port,
                }
            }
        }
    end
  end
end
