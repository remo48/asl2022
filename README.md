# Applied Security Laboratory - AS22

This is the repository of group 7 of the ASL course

## Client

### Accounts
Users for client vm: 
| **username** | **password** |
|--------------|--------------|
| admin        | admin123     |
| alice        | alice123     |

On the admin user, the certificate and private key "admin.p12" is stored to log in to the admin interface. 

### Installation (already done)
The client vm has a default GUI installed and uses the standard US keyboard layout. The Virtualbox guest additions can be installed by the following steps:

    sudo apt install dkms linux-headers-$(uname -r) build-essential

After that, an optical drive with the guest additions CD must be added in the virtual box GUI.
The CD can be mounted and executed to install the guest additions.

## Config
The configuration machine can be accessed through ssh from the admin account on the client machine

    ssh admin@config

All systems are provisioned and maintained through ansible. The ansible user has ssh access to all machines. To log in as the ansible user, execute the following

    sudo -iu ansible

The ansible playbooks used to provision the system are stored in the folder `ansible`. All hosts are stored in `/etc/hosts` and can be accessed through one of the following hostnames:

* web
* ca
* backup
* client
* db
* config

## Frontend
The client machine has a desktop with an instance of firefox installed. The root certificate is already installed in the browser and the web application can be accessed through https://www.imovies.ch or https://imovies.ch

## Initial Setup (already done)

### Requirements
* Vagrant
* Virtualbox

### Installation
The infrastructure can be initially installed using vagrant. Change in the project directory and execute the following command

    vagrant up

This creates the virtualbox vm's and sets up the ansible user with ssh keys. If everything is done, the machines can be provisioned. Log in to the config vm and change into the ansible folder of the ansible user. 

    vagrant ssh config
    sudo -iu ansible
    cd ansible

Before running a playbook, make sure to install the requirements

    ansible-galaxy install -r requirements.txt

If everything is setup correctly, the following command should run without errors and indicate, that every host is up

    ansible all -m ping -i production

After that, the machines can be provisioned by running the `site.yml` playbook

    ansible-playbook -i production site.yml

If everything successfully runs through, the system should be ready. All further administration must be done via the client vm's admin account. Log in to the admin account and ssh into the config vm

    ssh admin@config
    sudo -iu ansible
    cd ansible

At last, the following playbook can be run to harden the system

    ansible-playbook -i production hardening.yml

## Contributors
* Tobias Lüscher - [tobiaslue](https://github.com/tobiaslue)
* Julian Neff - [neffjulian](https://github.com/neffjulian)
* Remo Kellenberger - [remo48](https://github.com/remo48)
* Georgios Papadopoulos - [georgepapad88](https://github.com/georgepapad88)