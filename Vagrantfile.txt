# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.synced_folder ".", "/vagrant"
  config.vm.provider :virtualbox do |vb|
    vb.gui = true
  end
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install python3-pip -y
    python3.8 -m pip install matplotlib scapy pytest
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
    apt-get install mininet tshark -y
    apt-get install python -y
    git clone https://github.com/mininet/mininet
    mininet/util/install.sh -w
    python3.8 -m pip install ryu
  SHELL
end
