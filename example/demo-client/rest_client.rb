require_relative '../../lib/middleware/egress/aws_faraday_connection'

conn = BuildSecurity::Egress::AwsFaradayConnection.new

resp = conn.get('http://ec2-13-127-156-48.ap-south-1.compute.amazonaws.com:8000')

if resp.success?
    puts "Successfully connected to service"
else
    puts "Could not connect to service"
end
