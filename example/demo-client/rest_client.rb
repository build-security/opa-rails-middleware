require_relative '../../lib/middleware/egress/inter_instance_connection'

conn = Middleware::Egress::AwsInterInstanceConnection.new

resp = conn.get('http://ec2-13-127-156-48.ap-south-1.compute.amazonaws.com:8000')

if resp.success?
    print("Successfully connected to service\n")
else
    print("Could not connect to service\n")
end
