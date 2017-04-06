$rsyslog_8 = <<SCRIPT
sudo apt-get update
sudo apt-get install -y python-software-properties software-properties-common
sudo add-apt-repository ppa:adiscon/v8-stable 
sudo apt-get update
sudo apt-get install -y rsyslog

sudo cat <<EOF >> /root/.bashrc
export LANG=C
export LC_ALL=C
EOF

sudo cat <<EOF >> /home/vagrant/.bashrc
export LANG=C
export LC_ALL=C
EOF

SCRIPT

$rsyslog_server = <<SCRIPT
sudo cat <<EOF > /etc/rsyslog.d/server.conf
\\$ModLoad imudp
\\$UDPServerRun 514
EOF

sudo sed -i 's/.*RepeatedMsgReduction.*/\$RepeatedMsgReduction off/g' /etc/rsyslog.conf

sudo service rsyslog restart

sudo apt-get update
sudo apt-get install -y sendmail sendmail-bin mailutils pcregrep

SCRIPT

$rsyslog_client = <<SCRIPT
sudo cat <<EOF >> /etc/rsyslog.d/client.conf
*.*   @192.168.56.10:514
EOF
sudo service rsyslog restart
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.synced_folder ".", "/opt/SEC-notify"
  config.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "1024"]
  end
  config.vm.define "server" do |server|
        server.vm.hostname = "server"
        server.vm.network "private_network", 
          ip: "192.168.56.10"
        server.vm.provision "shell", 
          inline: $rsyslog_8
        server.vm.provision "shell", 
          inline: $rsyslog_server
  end
  config.vm.define "client" do |client|
        client.vm.hostname = "client"
        client.vm.network "private_network", 
          ip: "192.168.56.11"
        client.vm.provision "shell", 
          inline: $rsyslog_client
  end

end