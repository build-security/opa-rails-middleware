# frozen_string_literal: true

require 'aws-sdk-ec2'
require 'faraday'

module Middleware
    module Egress
        @@awsIdentityDocument = nil
        @@awsSignature = nil

        def self.getAwsMetadata(metadata_options)
            # TODO(yashtewari): Make thread-safe
            if @@awsIdentityDocument.nil?
                ec2_metadata = Aws::EC2Metadata.new(metadata_options)

                @@awsIdentityDocument = ec2_metadata.get('/latest/dynamic/instance-identity/document').delete(" \t\r\n")
                @@awsSignature = ec2_metadata.get('/latest/dynamic/instance-identity/pkcs7').delete(" \t\r\n")

                return @@awsIdentityDocument, @@awsSignature
            end
        end

        class InjectAwsIdentityDocument < Faraday::Middleware
            def initialize(app, metadata_options = {})
                super(app)

                @metadata_options = metadata_options
                @app = app
            end

            def on_request(env)
                id, sign = Middleware::Egress::getAwsMetadata(@metadata_options)
                
                env.request_headers['Aws-Identity-Document'] = id
                env.request_headers['Aws-Signature'] = sign
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
