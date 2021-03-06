#
# Author:: Seth Chisamore (<schisamo@opscode.com>)
# Author:: Matt Ray (<matt@opscode.com>)
# Copyright:: Copyright (c) 2011-2013 Opscode, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'fog'

class Chef
  class Knife
    module OpenstackBase

      # :nodoc:
      # Would prefer to do this in a rational way, but can't be done b/c of
      # Mixlib::CLI's design :(
      def self.included(includer)
        includer.class_eval do

          deps do
            require 'chef/json_compat'
            require 'chef/knife'
            require 'readline'
            Chef::Knife.load_deps
          end

          option :openstack_username,
            :short => "-A USERNAME",
            :long => "--openstack-username KEY",
            :description => "Your OpenStack Username",
            :proc => Proc.new { |key| Chef::Config[:knife][:openstack_username] = key }

          option :openstack_password,
            :short => "-K SECRET",
            :long => "--openstack-password SECRET",
            :description => "Your OpenStack Password",
            :proc => Proc.new { |key| Chef::Config[:knife][:openstack_password] = key }

          option :openstack_tenant,
            :short => "-T NAME",
            :long => "--openstack-tenant NAME",
            :description => "Your OpenStack Tenant NAME",
            :proc => Proc.new { |key| Chef::Config[:knife][:openstack_tenant] = key }

          option :openstack_auth_url,
            :long => "--openstack-api-endpoint ENDPOINT",
            :description => "Your OpenStack API endpoint",
            :proc => Proc.new { |endpoint| Chef::Config[:knife][:openstack_auth_url] = endpoint }

          option :region,
            :long => "--region REGION",
            :description => "Your OpenStack region",
            :proc => Proc.new { |key| Chef::Config[:knife][:region] = key }

          option :openstack_insecure,
            :long => "--insecure",
            :description => "Ignore SSL certificate on the Auth URL",
            :boolean => true,
            :default => false,
            :proc => Proc.new { |key| Chef::Config[:knife][:openstack_insecure] = key }
        end
      end

      def connection
        Chef::Log.debug("openstack_username #{Chef::Config[:knife][:openstack_username]}")
        Chef::Log.debug("openstack_auth_url #{Chef::Config[:knife][:openstack_auth_url]}")
        Chef::Log.debug("openstack_tenant #{Chef::Config[:knife][:openstack_tenant]}")
        Chef::Log.debug("openstack_insecure #{Chef::Config[:knife][:openstack_insecure].to_s}")

        @connection ||= begin
          connection = Fog::Compute.new(
            :provider => 'OpenStack',
            :openstack_username => Chef::Config[:knife][:openstack_username],
            :openstack_api_key => Chef::Config[:knife][:openstack_password],
            :openstack_auth_url => Chef::Config[:knife][:openstack_auth_url],
            :openstack_tenant => Chef::Config[:knife][:openstack_tenant],
            :openstack_region => Chef::Config[:knife][:region],
            :connection_options => {
              :ssl_verify_peer => !Chef::Config[:knife][:openstack_insecure],
              :read_timeout => 300,
              :debug_request => true,
              :debug_response => true
            }
            )
                        rescue Excon::Errors::Unauthorized => e
                          ui.fatal("Connection failure, please check your OpenStack username and password.")
                          exit 1
                        rescue Excon::Errors::SocketError => e
                          ui.fatal("Connection failure, please check your OpenStack authentication URL.")
                          exit 1
                        end
      end

      def network_service
        @network_service ||= begin
          network_service = Fog::Network.new(
            :provider => 'OpenStack',
            :openstack_username => Chef::Config[:knife][:openstack_username],
            :openstack_api_key => Chef::Config[:knife][:openstack_password],
            :openstack_auth_url => Chef::Config[:knife][:openstack_auth_url],
            :openstack_tenant => Chef::Config[:knife][:openstack_tenant],
            :openstack_region => Chef::Config[:knife][:region],
            :connection_options => {
              :ssl_verify_peer => !Chef::Config[:knife][:openstack_insecure],
              :debug_request => true,
              :debug_response => true
            }
          )
        rescue Excon::Errors::Unauthorized => e
          ui.fatal("Connection failure, please check your OpenStack username and password.")
          exit 1
        rescue Excon::Errors::SocketError => e
          ui.fatal("Connection failure, please check your OpenStack authentication URL.")
          exit 1
        end
      end

      def locate_config_value(key)
        key = key.to_sym
        Chef::Config[:knife][key] || config[key]
      end

      def msg_pair(label, value, color=:cyan)
        if value && !value.to_s.empty?
          puts "#{ui.color(label, color)}: #{value}"
        end
      end

      def validate!(keys=[:openstack_username, :openstack_password, :openstack_auth_url])
        errors = []

        keys.each do |k|
          pretty_key = k.to_s.gsub(/_/, ' ').gsub(/\w+/){ |w| (w =~ /(ssh)|(aws)/i) ? w.upcase  : w.capitalize }
          if Chef::Config[:knife][k].nil?
            errors << "You did not provided a valid '#{pretty_key}' value."
          end
        end

        if errors.each{|e| ui.error(e)}.any?
          exit 1
        end
      end

      # http://tickets.opscode.com/browse/KNIFE-248
      def primary_private_ip_address(server)
        if server.addresses['private']
          return server.addresses['private'].last['addr']
        elsif server.private_ip_addresses
          return server.private_ip_addresses.last
        end
      end

      #we use last since the floating IP goes there
      def primary_public_ip_address(server)
        if server.addresses['public']
          return server.addresses['public'].last['addr']
        elsif server.public_ip_addresses
          return server.public_ip_addresses.last
        end
      end

      def retryable(options = {}, &block)
        retry_exceptions = options[:on] || [Exception]
        timeout = options[:timeout] || 60
        start = Time.now
        failures = 0

        begin
          return yield
        rescue *retry_exceptions
          if Time.now - start > timeout
            raise "Operation timeout"
          end

          Chef::Log.debug("Catch exception, retrying")
          failures += 1
          sleep (((2 ** failures) -1) * 0.1)

          retry
        end
      end
    end
  end
end


