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

require 'chef/knife/openstack_base'
require 'yaml'

class Chef
  class Knife
    class OpenstackServerCreate < Knife

      include Knife::OpenstackBase

      deps do
        require 'fog'
        require 'readline'
        require 'chef/json_compat'
        require 'chef/knife/bootstrap'
        Chef::Knife::Bootstrap.load_deps
      end

      banner "knife openstack server create (options)"

      attr_accessor :initial_sleep_delay

      option :flavor,
      :short => "-f FLAVOR_ID",
      :long => "--flavor FLAVOR_ID",
      :description => "The flavor ID of server (m1.small, m1.medium, etc)",
      :proc => Proc.new { |f| Chef::Config[:knife][:flavor] = f }

      option :image,
      :short => "-I IMAGE_ID",
      :long => "--image IMAGE_ID",
      :description => "The image ID for the server",
      :proc => Proc.new { |i| Chef::Config[:knife][:image] = i }

      option :security_groups,
      :short => "-G X,Y,Z",
      :long => "--groups X,Y,Z",
      :description => "The security groups for this server",
      :default => ["default"],
      :proc => Proc.new { |groups| groups.split(',') }

      option :chef_node_name,
      :short => "-N NAME",
      :long => "--node-name NAME",
      :description => "The Chef node name for your new node"

      option :floating_ip,
      :short => "-a [IP]",
      :long => "--floating-ip [IP]",
      :default => "-1",
      :description => "Request to associate a floating IP address to the new OpenStack node. Assumes IPs have been allocated to the project. Specific IP is optional."

      option :allocate_floating_ip,
      :long => "--auto-alloc-floating-ip",
      :boolean => true,
      :default => false,
      :description => "Allocate a floating IP address if a floating IP is requested and none of allocated floating IPs is available."

      option :private_network,
      :long => "--private-network",
      :description => "Use the private IP for bootstrapping rather than the public IP",
      :boolean => true,
      :default => false

      option :ssh_key_name,
      :short => "-S KEY",
      :long => "--ssh-key KEY",
      :description => "The OpenStack SSH keypair id",
      :proc => Proc.new { |key| Chef::Config[:knife][:openstack_ssh_key_id] = key }

      option :ssh_user,
      :short => "-x USERNAME",
      :long => "--ssh-user USERNAME",
      :description => "The ssh username",
      :default => "root"

      option :ssh_password,
      :short => "-P PASSWORD",
      :long => "--ssh-password PASSWORD",
      :description => "The ssh password"

      option :identity_file,
      :short => "-i IDENTITY_FILE",
      :long => "--identity-file IDENTITY_FILE",
      :description => "The SSH identity file used for authentication"

      option :prerelease,
      :long => "--prerelease",
      :description => "Install the pre-release chef gems"

      option :bootstrap_version,
      :long => "--bootstrap-version VERSION",
      :description => "The version of Chef to install",
      :proc => Proc.new { |v| Chef::Config[:knife][:bootstrap_version] = v }

      option :distro,
      :short => "-d DISTRO",
      :long => "--distro DISTRO",
      :description => "Bootstrap a distro using a template; default is 'chef-full'",
      :proc => Proc.new { |d| Chef::Config[:knife][:distro] = d },
      :default => "chef-full"

      option :template_file,
      :long => "--template-file TEMPLATE",
      :description => "Full path to location of template to use",
      :proc => Proc.new { |t| Chef::Config[:knife][:template_file] = t },
      :default => false

      option :run_list,
      :short => "-r RUN_LIST",
      :long => "--run-list RUN_LIST",
      :description => "Comma separated list of roles/recipes to apply",
      :proc => lambda { |o| o.split(/[\s,]+/) },
      :default => []

      option :host_key_verify,
      :long => "--[no-]host-key-verify",
      :description => "Verify host key, enabled by default",
      :boolean => true,
      :default => true

      option :system_file_path,
      :long => "--system-file-path PATH",
      :description => "Full path to location of file to be injected into instance",
      :proc => Proc.new { |i| Chef::Config[:knife][:system_file_path] = i }

      option :system_file_content,
      :long => "--system-file-content CONTENT",
      :description => "The content of the system file",
      :proc => Proc.new { |i| Chef::Config[:knife][:system_file_content] = i },
      :default => ''

      option :openstack_hints,
      :long => "--openstack-hints HINTS",
      :description => "The openstack OS schedule hints",
      :proc => Proc.new { |i| Chef::Config[:knife][:openstack_hints] = i },
      :default => false

      def tcp_test_ssh(hostname)
        tcp_socket = TCPSocket.new(hostname, 22)
        readable = IO.select([tcp_socket], nil, nil, 5)
        if readable
          Chef::Log.debug("sshd accepting connections on #{hostname}, banner is #{tcp_socket.gets}")
          yield
          true
        else
          false
        end
      rescue Errno::ETIMEDOUT
        false
      rescue Errno::EPERM
        false
      rescue Errno::ECONNREFUSED
        sleep 2
        false
      rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH
        sleep 2
        false
      rescue Errno::ENETUNREACH
        sleep 2
        false
      rescue Errno::EINVAL
        sleep 2
        false
      ensure
        tcp_socket && tcp_socket.close
      end

      def run
        $stdout.sync = true

        validate!

        #servers require a name, generate one if not passed
        node_name = get_node_name(config[:chef_node_name])

        server_def = {
        :name => node_name,
        :image_ref => locate_config_value(:image),
        :flavor_ref => locate_config_value(:flavor),
        :security_groups => locate_config_value(:security_groups),
        :key_name => locate_config_value(:openstack_ssh_key_id)
      }
      if locate_config_value(:system_file_path)
        server_def[:personality] = [{
          "path" => locate_config_value(:system_file_path),
          "contents" => locate_config_value(:system_file_content)
        }]
      end
      if locate_config_value(:openstack_hints)
        server_def['os_scheduler_hints'] = parse_hints(locate_config_value(:openstack_hints))
      end

      Chef::Log.debug("Name #{node_name}")
      Chef::Log.debug("Image #{locate_config_value(:image)}")
      Chef::Log.debug("Flavor #{locate_config_value(:flavor)}")
      Chef::Log.debug("Requested Floating IP #{locate_config_value(:floating_ip)}")
      Chef::Log.debug("Security Groups #{locate_config_value(:security_groups)}")
      Chef::Log.debug("Creating server #{server_def}")

      begin
        server = connection.servers.create(server_def)
      rescue Excon::Errors::BadRequest => e
        response = Chef::JSONCompat.from_json(e.response.body)
        if response['badRequest']['code'] == 400
          if response['badRequest']['message'] =~ /Invalid flavorRef/
            ui.fatal("Bad request (400): Invalid flavor specified: #{server_def[:flavor_ref]}")
            exit 1
          else
            ui.fatal("Bad request (400): #{response['badRequest']['message']}")
            exit 1
          end
        else
          ui.fatal("Unknown server error (#{response['badRequest']['code']}): #{response['badRequest']['message']}")
          raise e
        end
      end

      msg_pair("Instance Name", server.name)
      msg_pair("Instance ID", server.id)

      print "\n#{ui.color("Waiting for server", :magenta)}"

      # wait for it to be ready to do stuff
      server.wait_for { print "."; ready? }

      puts("\n")

      msg_pair("Flavor", server.flavor['id'])
      msg_pair("Image", server.image['id'])
      msg_pair("SSH Identity File", config[:identity_file])
      msg_pair("SSH Keypair", server.key_name) if server.key_name
      msg_pair("SSH Password", server.password) if (server.password && !server.key_name)
      Chef::Log.debug("Addresses #{server.addresses}")
      msg_pair("Public IP Address", primary_public_ip_address(server)) if primary_public_ip_address(server)

      floating_address = locate_config_value(:floating_ip)
      Chef::Log.debug("Floating IP Address requested #{floating_address}")
      unless (floating_address == '-1') #no floating IP requested
        associated = associate_address(server, :selected_ip => floating_address)
        unless associated
          ui.error("Unable to assign a Floating IP from allocated IPs.")
          exit 1
        end
      end

      Chef::Log.debug("Addresses #{server.addresses}")
      Chef::Log.debug("Public IP Address actual: #{primary_public_ip_address(server)}") if primary_public_ip_address(server)

      msg_pair("Private IP Address", primary_private_ip_address(server)) if primary_private_ip_address(server)

      #which IP address to bootstrap
      bootstrap_ip_address = primary_public_ip_address(server) if primary_public_ip_address(server)
      if config[:private_network]
        bootstrap_ip_address = primary_private_ip_address(server)
      end

      Chef::Log.debug("Bootstrap IP Address: #{bootstrap_ip_address}")
      if bootstrap_ip_address.nil?
        ui.error("No IP address available for bootstrapping.")
        exit 1
      end

      bootstrap_retried = false
      begin
        print "\n#{ui.color("Waiting for sshd", :magenta)}"
        print(".") until tcp_test_ssh(bootstrap_ip_address) {
          sleep @initial_sleep_delay ||= 10
          puts("done")
        }

        retryable(:timeout => 120, :on => [Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Net::SSH::AuthenticationFailed]) do
          bootstrap_for_node(server, bootstrap_ip_address).run
        end
      rescue Net::SSH::Disconnect => e
        raise e if bootstrap_retried

        puts "Bootstrap failed, about to reboot server and try again."

        server.reboot
        print "\n#{ui.color("Waiting for server reboot", :magenta)}"
        server.wait_for { print "."; ready? }

        bootstrap_retried = true
        retry
      end

      puts "\n"
      msg_pair("Instance Name", server.name)
      msg_pair("Instance ID", server.id)
      msg_pair("Flavor", server.flavor['id'])
      msg_pair("Image", server.image['id'])
      msg_pair("SSH Keypair", server.key_name) if server.key_name
      msg_pair("SSH Password", server.password) if (server.password && !server.key_name)
      msg_pair("Public IP Address", primary_public_ip_address(server)) if primary_public_ip_address(server)
      msg_pair("Private IP Address", primary_private_ip_address(server)) if primary_private_ip_address(server)
      msg_pair("Environment", config[:environment] || '_default')
      msg_pair("Run List", config[:run_list].join(', '))
    rescue Fog::Errors::Error => e
      raise e, e.verbose, e.backtrace if e.verbose
      raise e
    end

    def bootstrap_for_node(server, bootstrap_ip_address)
      bootstrap = Chef::Knife::Bootstrap.new
      bootstrap.name_args = [bootstrap_ip_address]
      bootstrap.config[:run_list] = config[:run_list]
      bootstrap.config[:ssh_user] = config[:ssh_user]
      bootstrap.config[:ssh_password] = server.password
      bootstrap.config[:identity_file] = config[:identity_file]
      bootstrap.config[:host_key_verify] = config[:host_key_verify]
      bootstrap.config[:chef_node_name] = server.name
      bootstrap.config[:prerelease] = config[:prerelease]
      bootstrap.config[:bootstrap_version] = locate_config_value(:bootstrap_version)
      bootstrap.config[:distro] = locate_config_value(:distro)
      bootstrap.config[:use_sudo] = true unless config[:ssh_user] == 'root'
      bootstrap.config[:template_file] = locate_config_value(:template_file)
      bootstrap.config[:environment] = config[:environment]
      # let ohai know we're using OpenStack
      Chef::Config[:knife][:hints] ||= {}
      Chef::Config[:knife][:hints]['openstack'] ||= {}
      bootstrap
    end

    def flavor
      @flavor ||= connection.flavors.get(locate_config_value(:flavor))
    end

    def image
      @image ||= connection.images.get(locate_config_value(:image))
    end

    def is_floating_ip_valid
      address = locate_config_value(:floating_ip)
      if address.nil? || address == '-1' #no floating IP requested
        return true
      end
      addresses = connection.addresses
      return false if addresses.empty? #no floating IPs
      #floating requested with value
      if addresses.find_index {|a| a.ip == address}
        return true
      else
        return false #requested floating IP does not exist
      end
    end

    def validate!
      super([:image, :openstack_username, :openstack_password, :openstack_auth_url])

      if flavor.nil?
        ui.error("You have not provided a valid flavor ID. Please note the options for this value are -f or --flavor.")
        exit 1
      end

      if image.nil?
        ui.error("You have not provided a valid image ID. Please note the options for this value are -I or --image.")
        exit 1
      end

      if !is_floating_ip_valid
        ui.error("You have either requested an invalid floating IP address or none are available.")
        exit 1
      end
    end

    #generate a random name if chef_node_name is empty
    def get_node_name(chef_node_name)
      return chef_node_name unless chef_node_name.nil?
      #lazy uuids
      chef_node_name = "os-"+rand.to_s.split('.')[1]
    end

    def associate_address(server, options={})
      free_floating_ip = nil

      lock_floating_ips do
        begin
          floating_ip = network_service.floating_ips.find{ |ip| ip.port_id.nil? }
          if floating_ip.nil? && locate_config_value(:allocate_floating_ip)
            tenant = connection.tenants.find{ |t| t.name == Chef::Config[:knife][:openstack_tenant] }
            ext_net = network_service.networks.find{ |net| net.router_external }
            floating_ip = network_service.floating_ips.create(:floating_network_id => ext_net.id,
                                                              :tenant_id => tenant.id)
          end

          server_fixed_ip = server.networks.map{ |n| n.addresses.last }.last
          port = network_service.ports.find{ |p| p.fixed_ips.any?{ |fip| fip["ip_address"] == server_fixed_ip} }
          raise "Unexpected missing of port for server" unless port
          network_service.associate_floating_ip(floating_ip.id, port.id)
          free_floating_ip = floating_ip.floating_ip_address
        rescue Fog::Errors::NotFound
          addresses = connection.addresses
          address = addresses.find{ |addr| addr.fixed_ip.nil? }
          if address.nil? && locate_config_value(:allocate_floating_ip)
            address = addresses.create
          end

          if address
            server.associate_address(address.ip)
            free_floating_ip = address.ip
          end
        end
      end

      return false if free_floating_ip.nil?

      (server.addresses['public'] ||= Array.new).push({"version" => 4, "addr" => free_floating_ip})
      msg_pair("Floating IP Address", free_floating_ip)
      true
    end

    FLOATING_IPS_LOCK_FILE = "/tmp/floating_ips.lock"

    def lock_floating_ips
      raise "Unexpected missing of block" unless block_given?

      File.open(FLOATING_IPS_LOCK_FILE, "w") do |lock|
        lock.flock(File::LOCK_EX)
        yield
      end
    end

    def parse_hints(str)
      hints = Hash.new
      str.split(",").each do |hint|
        key, value = *hint.split("=")
        hints[key] = value
      end
      hints
    end
  end
end
end
