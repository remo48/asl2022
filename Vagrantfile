VM_BOX="debian/bullseye64"

MEMORY=512
CLIENT_MEMORY=1024
CPU_CAP_PERCENTAGE=50

INTERNAL_NETWORK="asl-internal"
PUBLIC_NETWORK="asl-public"


# definition of machines 
# IMPORTANT: if something is changed here, inventory must be 
# changed as well
clientvm = {
  :name => "client",
  :pub_ip => "192.168.99.100"
}

configvm = {
  :name => "config",
  :ip => "10.0.99.10",
  :pub_ip => "192.168.99.10"
}

hosts = {
  "web" => {
    :ip => "10.0.99.20",
    :pub_ip => "192.168.99.20"
  },
  "db" => {
    :ip => "10.0.99.30"
  },
  "backup" => {
    :ip => "10.0.99.40"
  },
  "ca" => {
    :ip => "10.0.99.50"
  }
}

Vagrant.configure("2") do |config|

  config.vm.provider "virtualbox" do |vb|
		vb.customize ["modifyvm", :id, "--cpuexecutioncap", CPU_CAP_PERCENTAGE]
	end

  # set up internal hosts
  hosts.each do |hostname, info|
    config.vm.define hostname do |hostconf|
      hostconf.vm.box = VM_BOX
      hostconf.vm.hostname = hostname
      hostconf.vm.network "private_network", ip: "#{info[:ip]}", virtualbox__intnet: INTERNAL_NETWORK

      # disable synced folder
      hostconf.vm.synced_folder ".", "/vagrant", disabled: true

      # add public ip address
      if info.key?(:pub_ip)
        hostconf.vm.network "private_network", ip: "#{info[:pub_ip]}", virtualbox__intnet: PUBLIC_NETWORK
      end

      # configure virtualbox
      hostconf.vm.provider "virtualbox" do |vb|
        vb.name = "asl-#{hostname}"
        vb.memory = MEMORY
      end

      # add host names to /etc/hosts
      hosts.each do |peer_hostname, peer_info|
        hostconf.vm.provision "shell", inline: <<-SCRIPT
          echo "#{peer_info[:ip]} #{peer_hostname}" | sudo tee -a /etc/hosts
        SCRIPT
      end
    end
  end
  
  # setup client machine
  config.vm.define clientvm[:name] do |clientconf|
    clientconf.vm.box = VM_BOX
    clientconf.vm.hostname = clientvm[:name]
    clientconf.vm.network "private_network", ip: "#{clientvm[:pub_ip]}", virtualbox__intnet: PUBLIC_NETWORK

    # disable synced folder
    clientconf.vm.synced_folder ".", "/vagrant", disabled: true

    # configure virtualbox
    clientconf.vm.provider "virtualbox" do |vb|
      vb.name = "asl-#{clientvm[:name]}"
      vb.memory = CLIENT_MEMORY
    end

    # add hosts with public ip to /etc/hosts
    hosts.each do |peer_hostname, peer_info|
      if peer_info.key?(:pub_ip)
        clientconf.vm.provision "shell", inline: <<-SCRIPT
          echo "#{peer_info[:pub_ip]} #{peer_hostname}" | sudo tee -a /etc/hosts
        SCRIPT
      end
    end

    # install desktop environment and firefox (TODO maybe write ansible playbook for setup)
    # clientconf.vm.provision "shell", inline: <<-SCRIPT
    #   sudo apt-get update
    #   sudo apt-get install -y xfce4
    #   sudo apt-get install -y virtualbox-guest-dkms virtualbox-guest-utils virtualbox-guest-x11 firefox-esr
    # SCRIPT
  end

  # setup config machine
  config.vm.define configvm[:name] do |configconf|
    configconf.vm.box = VM_BOX
    configconf.vm.hostname= configvm[:name]
    configconf.vm.network "private_network", ip: "#{configvm[:pub_ip]}", virtualbox__intnet: PUBLIC_NETWORK
    configconf.vm.network "private_network", ip: "#{configvm[:ip]}", virtualbox__intnet: INTERNAL_NETWORK
    
    configconf.vm.provider "virtualbox" do |vb|
      vb.name = "asl-#{configvm[:name]}"
      vb.memory = MEMORY
    end

    hosts.each do |peer_hostname, peer_info|
      configconf.vm.provision "shell", inline: <<-SCRIPT
        echo "#{peer_info[:ip]} #{peer_hostname}" | sudo tee -a /etc/hosts
      SCRIPT
    end

    # provision machines with config as master
    configconf.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "setup.yml"
      ansible.limit = "all"
      ansible.install = true
      ansible.inventory_path = "inventory"
      ansible.provisioning_path = "/vagrant/shared/ansible"
    end
  end

end
