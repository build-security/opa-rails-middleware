# frozen_string_literal: true

require 'aws-sdk-ec2'
require 'base64'
require 'faraday'

module BuildSecurity
    module Egress
        def self.getAwsMetadata(metadata_options)
            # TODO(yashtewari): Cache signed instance metadata.
            ec2_metadata = Aws::EC2Metadata.new(metadata_options)

            signed_data = ec2_metadata.get('/latest/dynamic/instance-identity/pkcs7')
            signed_data_pem = "-----BEGIN PKCS7-----\n#{signed_data}\n-----END PKCS7-----"
            Base64.urlsafe_encode64(signed_data_pem)
        end

        ##
        # Faraday middleware that injects AWS IMDS signed data into outgoing requests.
        class InjectAwsIdentityDocument < Faraday::Middleware
            def initialize(app, metadata_options = {})
                super(app)

                @metadata_options = metadata_options
                @app = app
            end

            def on_request(env)
                signed_data = BuildSecurity::Egress::getAwsMetadata(@metadata_options)
                
                env.request_headers['Aws-Signed-Metadata'] = signed_data
            end
        end

        ##
        # Works just like a Faraday::Connection except that it is meant to be run on AWS EC2
        # instances, where it can fetch and inject AWS IMDS signed data into outgoing requests.
        class AwsFaradayConnection < Faraday::Connection
            def initialize(url = nil, options = nil)
                # TODO(yashtewari): Accept AWS IMDS metadata options and pass to middleware.
                super(url, options) do |conn|
                    conn.use InjectAwsIdentityDocument
                end
            end
        end
    end
end
