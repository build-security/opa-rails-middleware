# frozen_string_literal: true

require 'aws-sdk-ec2'
require 'base64'
require 'faraday'

module Middleware
    module Egress
        @@awsIdentityDocument = nil
        @@awsSignature = nil

        def self.getAwsMetadata(metadata_options)
            # TODO(yashtewari): Make thread-safe
            if @@awsIdentityDocument.nil?
                ec2_metadata = Aws::EC2Metadata.new(metadata_options)

                signed_data = ec2_metadata.get('/latest/dynamic/instance-identity/pkcs7')
                signed_data_pem = "-----BEGIN PKCS7-----\n#{signed_data}\n-----END PKCS7-----"
                Base64.urlsafe_encode64(signed_data_pem)
            end
        end

        class InjectAwsIdentityDocument < Faraday::Middleware
            def initialize(app, metadata_options = {})
                super(app)

                @metadata_options = metadata_options
                @app = app
            end

            def on_request(env)
                signed_data = Middleware::Egress::getAwsMetadata(@metadata_options)
                
                env.request_headers['Aws-Signed-Metadata'] = signed_data
            end
        end

        class AwsInterInstanceConnection < Faraday::Connection
            def initialize(url = nil, options = nil)
                super(url, options) do |conn|
                    conn.use InjectAwsIdentityDocument
                end
            end
        end
    end
end
