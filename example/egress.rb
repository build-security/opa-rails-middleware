require_relative 'lib/middleware/egress/inter_instance_connection'

conn = Middleware::Egress::AwsInterInstanceConnection.new

conn.get('http://google.com')
