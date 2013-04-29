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
      msg_pair("Public IP Address", primary_public_ip_address(server.addresses)) if primary_public_ip_address(server.addresses)

      floating_address = locate_config_value(:floating_ip)
      Chef::Log.debug("Floating IP Address requested #{floating_address}")
      unless (floating_address == '-1') #no floating IP requested
        #addresses = connection.addresses
        ##floating requested without value
        #if floating_address.nil?
        #  free_floating = addresses.find_index {|a| a.fixed_ip.nil?}
        #  if free_floating.nil? #no free floating IP found
        #    ui.error("Unable to assign a Floating IP from allocated IPs.")
        #    exit 1
        #  else
        #    floating_address = addresses[free_floating].ip
        #  end
        #end
        associated = associate_address(server, :selected_ip => floating_address) #TODO
        unless associated
          ui.error("Unable to assign a Floating IP from allocated IPs.")
          exit 1
        end
      end

      Chef::Log.debug("Addresses #{server.addresses}")
      Chef::Log.debug("Public IP Address actual: #{primary_public_ip_address(server.addresses)}") if primary_public_ip_address(server.addresses)

      msg_pair("Private IP Address", primary_private_ip_address(server.addresses)) if primary_private_ip_address(server.addresses)

      #which IP address to bootstrap
      bootstrap_ip_address = primary_public_ip_address(server.addresses) if primary_public_ip_address(server.addresses)
      if config[:private_network]
        bootstrap_ip_address = primary_private_ip_address(server.addresses)
      end

      Chef::Log.debug("Bootstrap IP Address: #{bootstrap_ip_address}")
      if bootstrap_ip_address.nil?
        ui.error("No IP address available for bootstrapping.")
        exit 1
      end

      print "\n#{ui.color("Waiting for sshd", :magenta)}"

      print(".") until tcp_test_ssh(bootstrap_ip_address) {
        sleep @initial_sleep_delay ||= 10
        puts("done")
      }

      retryable(:timeout => 120, :on => [Errno::ECONNREFUSED, Net::SSH::AuthenticationFailed]) do
        bootstrap_for_node(server, bootstrap_ip_address).run
      end

      puts "\n"
      msg_pair("Instance Name", server.name)
      msg_pair("Instance ID", server.id)
      msg_pair("Flavor", server.flavor['id'])
      msg_pair("Image", server.image['id'])
      msg_pair("SSH Keypair", server.key_name) if server.key_name
      msg_pair("SSH Password", server.password) if (server.password && !server.key_name)
      msg_pair("Public IP Address", primary_public_ip_address(server.addresses)) if primary_public_ip_address(server.addresses)
      msg_pair("Private IP Address", primary_private_ip_address(server.addresses)) if primary_private_ip_address(server.addresses)
      msg_pair("Environment", config[:environment] || '_default')
      msg_pair("Run List", config[:run_list].join(', '))
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
      if address == '-1' #no floating IP requested
        return true
      end
      addresses = connection.addresses
      return false if addresses.empty? #no floating IPs
      #floating requested without value
      if address.nil?
        if addresses.find_index {|a| a.fixed_ip.nil?}
          return true
        else
          return false #no floating IPs available
        end
      end
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

    def retryable(options = {}, &block)
      retry_exceptions, timeout = options[:on], options[:timeout]
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

    def associate_address(server)
      ip = get_floating_ip
      return false unless ip

      server.associate_address(ip)
      (server.addresses['public'] ||= Array.new).push({"version" => 4, "addr" => ip})
      msg_pair("Floating IP Address", ip)
      return true
    end

    module AddrState
      UNASSOCIATED = "unassociated"
      ASSOCIATING = "associating"
      ASSOCIATED = "associated"
    end

    def get_floating_ip
      lock_file = "/tmp/floating_ips.lock"
      data_file = "/tmp/floating_ips.yaml"

      File.open(lock_file, "w") do |lock|
        lock.flock(File::LOCK_EX)

        unless File.exists?(data_file)
          File.open(data_file, "w") do |fout|
            addrs = Array.new
            connection.addresses.each do |address|
              addrs << {:ip => address.ip, :state => address.instance_id ? AddrState::ASSOCIATED : AddrState::UNASSOCIATED, :last_updated => Time.now}
            end
            fout.write(addrs.to_yaml)
          end
        end

        # pull floating ips' info from file
        cached_addrs = YAML.load_file(data_file)
        raise "Unexpected data format in file #{data_file}" unless cached_addrs.class == Array

        # update the floating ips info
        cached_addrs.each do |cached_addr|
          connection.addresses.each do |address|
            next if cached_addr[:ip] != address.ip
            if address.instance_id && cached_addr[:state] == AddrState::ASSOCIATING
              set_addr_state(cached_addr, AddrState::ASSOCIATED)
            elsif address.instance_id.nil? && cached_addr[:state] == AddrState::ASSOCIATED
              set_addr_state(cached_addr, AddrState::UNASSOCIATED)
            elsif associate_timeout(cached_addr)
              set_addr_state(cached_addr, AddrState::UNASSOCIATED)
            end
          end
        end

        # choose a floating ip that haven't associated and associating with any instance
        my_ip = nil
        cached_addrs.each do |addr|
          if addr[:state] == AddrState::UNASSOCIATED
            my_ip = addr[:ip]
            set_addr_state(addr, AddrState::ASSOCIATING)
            break
          end
        end

        # dump the floating ips' info back to file
        File.open(data_file, "w") do |fout|
          fout.write(cached_addrs.to_yaml)
        end

        my_ip
      end
    end

    def set_addr_state(addr, state)
      addr[:state] = state
      addr[:last_updated] = Time.now
    end

    def associate_timeout(addr)
      timeout = 120
      addr[:state] == AddrState::ASSOCIATING && Time.now - addr[:last_updated] > timeout
    end
  end
end
end
