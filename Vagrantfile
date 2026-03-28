Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "trans-proxy-e2e"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  config.vm.synced_folder ".", "/home/vagrant/trans_proxy"

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y build-essential curl nftables iproute2 pkg-config
    # Install Rust for vagrant user
    su - vagrant -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
  SHELL
end
