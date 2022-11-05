Vault-gateway-login
===================

This application enables a specific workflow: you need to access secrets on some remote machine using *HashiCorp Vault*, but need to authenticate to Vault using a certificate that is only found locally (as a file on your workstation or laptop, or in a hardware security key such as a YubiKey).

It works simply by opening a connection to the remote machine (the *gateway*) via SSH and binding the remote Vault to a local port. Vault login is performed locally (if previous token expired or new token requested), the extracted token is copied to the gateway, and a remote shell is opened on the gateway. The first SSH connection to the gateway is in "master" mode, and subsequent operations (token copying, remote shell) use a socket. Terminating the shell does not close the master connection, and it is reused if still connected.

Requires Python ≥ 3.8 and basic Unix tools such as *ssh* and *cURL*. To work with a security key, *p11tool* is needed and smart card daemon running.

Installation
------------
Simply copy the script to a location in your `$PATH`. The configuration file is `~/.vault-gateway-login.yaml` by default, it can be changed with the `--config` argument.

    git clone https://github.com/ymeiron/vault-gateway-login.git
    cp vault-gateway-login/config-example.yaml ~/.vault-gateway-login.yaml
    sudo cp -rp vault-gateway-login/vault-gateway-login.py /usr/local/bin/
    
Edit the file configuration file as needed.