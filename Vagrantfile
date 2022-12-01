VM_BOX="debian/bullseye64"

MEMORY=512
CLIENT_MEMORY=1024
CLIENT_VRAM=32
CPU_CAP_PERCENTAGE=50

INTERNAL_NETWORK="asl-internal"
PUBLIC_NETWORK="asl-public"

# password for initial key distribution
ANSIBLE_REMOTE_PASSWORD="6ac4!gHu3lLw"

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

$add_ssh_keys = <<-SCRIPT
# add ip addresses to host file
echo "$2 $1" | sudo tee -a /etc/hosts

# copy public key to authorized_keys on host machines
sudo sshpass -p "#{ANSIBLE_REMOTE_PASSWORD}" ssh-copy-id -i /home/ansible/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new ansible@$1

# add remote host to known_hosts of ansible
sudo su - ansible -c 'ssh -o StrictHostKeyChecking=accept-new ansible@$1 exit'

# remove password from ansible remote user
sudo sshpass -p "#{ANSIBLE_REMOTE_PASSWORD}" ssh ansible@$1 <<EOF
sudo passwd -d ansible
sudo usermod --lock ansible
EOF
SCRIPT

$add_remote_ansible_user = <<-SCRIPT
# configure sshd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config    
systemctl restart sshd.service

# add ansible user
sudo adduser --disabled-password --gecos "" ansible
echo "ansible:#{ANSIBLE_REMOTE_PASSWORD}" | sudo chpasswd
echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo EDITOR="tee -a" visudo
SCRIPT

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

      # add public ip address
      if info.key?(:pub_ip)
        hostconf.vm.network "private_network", ip: "#{info[:pub_ip]}", virtualbox__intnet: PUBLIC_NETWORK
      end

      # configure virtualbox
      hostconf.vm.provider "virtualbox" do |vb|
        vb.name = "asl-#{hostname}"
        vb.memory = MEMORY
      end

      hostconf.vm.provision "shell", inline: $add_remote_ansible_user

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

    # configure virtualbox
    clientconf.vm.provider "virtualbox" do |vb|
      vb.name = "asl-#{clientvm[:name]}"
      vb.memory = CLIENT_MEMORY
      vb.customize ["modifyvm", :id, "--vram", CLIENT_VRAM]
    end

    clientconf.vm.provision "shell", inline: $add_remote_ansible_user

    # add client to /etc/hosts
    clientconf.vm.provision "shell", inline: <<-SCRIPT
      echo "#{configvm[:pub_ip]} #{configvm[:name]}" | sudo tee -a /etc/hosts
    SCRIPT

    # add hosts with public ip to /etc/hosts
    hosts.each do |peer_hostname, peer_info|
      if peer_info.key?(:pub_ip)
        clientconf.vm.provision "shell", inline: <<-SCRIPT
          echo "#{peer_info[:pub_ip]} #{peer_hostname}" | sudo tee -a /etc/hosts
        SCRIPT
      end
    end
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

    configconf.vm.provision "shell", inline: <<-SCRIPT
      # install ansible
      sudo apt-get update
      sudo apt-get install -y ansible sshpass

      # add ansible user
      sudo adduser --disabled-password --gecos "" ansible
      echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo EDITOR="tee -a" visudo

      # generate private key for ansible user
      sudo su - ansible -c 'ssh-keygen -t ed25519 -f /home/ansible/.ssh/id_ed25519 -N ""'

      # copy ansible playbooks and inventory
      sudo cp -r /vagrant/shared/ansible /home/ansible
    SCRIPT

    hosts.each do |peer_hostname, peer_info|
      # add ssh acces for ansible user
      configconf.vm.provision "shell", inline: $add_ssh_keys, args: [peer_hostname, peer_info[:ip]]
    end

    configconf.vm.provision "shell", inline: $add_ssh_keys, args: [clientvm[:name], clientvm[:pub_ip]]

    # provision machines with config as master
    # configconf.vm.provision "ansible_local" do |ansible|
    #   ansible.playbook = "site.yml"
    #   ansible.limit = "all"
    #   ansible.install = true
    #   ansible.inventory_path = "production"
    #   ansible.provisioning_path = "/vagrant/shared/ansible"
    # end
  end
end
