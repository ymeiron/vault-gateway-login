#!/usr/bin/env python
import subprocess as sp
from typing import Optional, List
import argparse, logging, os, re, psutil, socket, json, signal, datetime, time, yaml
from dataclasses import dataclass

__version__ = '0.1.0'

def get_control_master_pid(ctl_path: str) -> Optional[int]:
    command = ['ssh', '-S', ctl_path, '-O', 'check', 'gw']
    logging.debug('Running command: ' + ' '.join(command))
    p = sp.Popen(command, stdout=sp.DEVNULL, stderr=sp.PIPE)
    _, stderr = p.communicate()
    p.wait()
    if p.returncode == 0:
        match = re.match(r'Master running \(pid=(\d+)\)', stderr.decode())
        if match:
            pid = int(match.groups()[0])
            return pid
        else:
            raise RuntimeError('Unexpected response when checking control master.')
    if p.returncode == 255:
        return None
    raise RuntimeError('Unknown return code when checking control master status.')

@dataclass
class Port_forwarding_spec:
    port: int
    host: str
    host_port: int

def start_control_master(
        host: str,
        ctl_path: str,
        port: Optional[int] = None,
        username: Optional[str] = None,
        port_forwarding: List[Port_forwarding_spec] = []
    ) -> None:
    try:
        os.remove(ctl_path)
    except:
        pass
    success_string = 'scinet-login-success-000'
    command = ['ssh', '-M', '-S', ctl_path, '-o', 'ControlPersist=yes']
    if not port is None:
        command += ['-p', str(port)]
    if not username is None:
        command += ['-l', username]
    for spec in port_forwarding:
        command += [f'-L{spec.port}:{spec.host}:{spec.host_port}']
    command += [host, 'echo ' + success_string]
    logging.debug('Running command: ' + ' '.join(command))
    p = sp.Popen(command, stdout=sp.PIPE, stderr=sp.PIPE)
    stdout, stderr = p.communicate()
    if stdout.decode().strip() != success_string:
        logging.error('Failure starting SSH control master')
        exit(1)

def get_pkcs11_uri(pkcs11_module_path: str) -> str:
    command = ['p11tool', f'--provider={pkcs11_module_path}', '--list-token-urls']
    logging.debug('Running command: ' + ' '.join(command))
    p = sp.Popen(command, stdout=sp.PIPE, stderr=sp.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode or len(stderr):
        raise RuntimeError('p11tool returned an error.')
    uri_list = stdout.decode().strip().splitlines()
    if uri_list:
        return uri_list[0]
    else:
        return ''

def get_forwarded_port(socket: str) -> Optional[int]:
    pid = get_control_master_pid(socket)
    p = psutil.Process(pid)
    for c in p.connections():
        if c.status == 'LISTEN':
            return c.laddr.port
    return None

def get_free_port() -> Optional[int]:
    for port in range(32768, 65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sock.connect_ex(('127.0.0.1', port)) != 0:
            return port

def perform_cert_login(pkcs11_module_path, port: int, data: dict = {}, sk_pin: str = '') -> dict:
    os.environ['PKCS11_MODULE_PATH'] = pkcs11_module_path

    pkcs11_uri = get_pkcs11_uri(pkcs11_module_path)
    if not pkcs11_uri:
        logging.error('Could not get PKCS #11 URI')
        exit(1)
    logging.info(f'PKCS #11 URI is {pkcs11_uri}')

    if sk_pin:
        pkcs11_uri += f';pin-value={sk_pin}'

    command = [
        'curl',
        '--insecure',
        '--cert', pkcs11_uri,
    ]
    if data:
        data_json = json.dumps(data)
        command += ['--request', 'POST', '--data', data_json]

    command += [f'https://127.0.0.1:{port}/v1/auth/cert/login']
    logging.debug('Running command: ' + ' '.join(command))

    p = sp.Popen(command, stdout=sp.PIPE, stderr=sp.DEVNULL)
    stdout, _ = p.communicate()

    response = json.loads(stdout)
    return response

def copy_vault_token_to_gw(token_path: str, ctl_path: str) -> None:
    command = ['scp', '-rp', '-o', f'ControlPath={ctl_path}', token_path, 'gw:']
    logging.debug('Running command: ' + ' '.join(command))
    p = sp.Popen(command, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    p.wait()
    if p.returncode != 0:
        logging.error('Error copying token to gateway')
        exit(1)

def get_token_expiration(login_json_path: str) -> Optional[float]:
    try:
        login_json_mtime = os.path.getmtime(login_json_path)
        with open(login_json_path, 'r') as f:
            login_json = json.load(f)
        token_expiration = login_json_mtime + login_json['auth']['lease_duration']
        logging.info(f'Previous token expiring at {token_expiration}')
        return token_expiration
    except:
        logging.info('No previous token found')
        return None

def get_renew_token(login_json_path: str) -> bool:
    token_expiration = get_token_expiration(login_json_path)
    renew_token = True
    if not token_expiration is None:
        unix_now = time.mktime(datetime.datetime.now().timetuple())
        renew_token = token_expiration < unix_now
    if renew_token:
        logging.info('Renewing token')
    else:
        logging.info('Not renewing token')
    return renew_token

def start_remote_session(ctl_path: str) -> None:
    signal.signal(signal.SIGINT, lambda signum, frame: None) # Prevents Python from catching ^C
    command = ['ssh', '-S', ctl_path, 'gw']
    logging.debug('Running command: ' + ' '.join(command))
    p = sp.Popen(command)
    p.wait()

if __name__ == '__main__': # help='show version information and exit',
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--config', help='configuration file path')
    parser.add_argument('--new-token', help='get a new token regardless of an unexpired token present', action='store_true')
    parser.add_argument('--exit', help='tell SSH control master to exit', action='store_true')
    args = parser.parse_args()
    
    config_path = os.path.join(os.environ['HOME'], '.vault-gateway-login.yaml')
    if args.config:
        config_path = args.config
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    log_level = getattr(logging, config['log_level'], logging.ERROR)
    logging.basicConfig(level=log_level, format='%(asctime)s: %(message)s')

    if args.exit:
        if (pid := get_control_master_pid(config['ctl_path'])) is not None:
            logging.info(f'SSH control master found at pid {pid}')
            command = ['ssh', '-S', config['ctl_path'], '-O', 'exit']
            logging.debug('Running command: ' + ' '.join(command))
            p = sp.Popen(command, stdout=sp.PIPE, stderr=sp.PIPE)
            try:
                p.wait(timeout=1)
            except sp.TimeoutExpired:
                logging.info('Cannot exit nicely, sending kill signal')
                os.kill(pid, signal.SIGKILL)
        else:
            logging.info('SSH control master not found')
        try:
            os.remove(config['ctl_path'])
            logging.info(f'Deleted socket {config["ctl_path"]}')
        except:
            pass
        exit(0)

    login_json_path = os.path.join(os.environ['HOME'], '.vault-login.json')
    token_path = os.path.join(os.environ['HOME'], '.vault-token')
    renew_token = args.new_token or get_renew_token(login_json_path)

    if (pid := get_control_master_pid(config['ctl_path'])) is not None:
        logging.info(f'SSH control master found at pid {pid}')
        local_vault_port = get_forwarded_port(config['ctl_path'])
        if local_vault_port is None:
            logging.error(f'Could not find the listening port of pid {pid}')
            exit(1)
        logging.info(f'SSH control master pid {pid} listening on port {local_vault_port}')
    else:
        local_vault_port = get_free_port()
        if local_vault_port is None:
            logging.error('Could not get a free port')
            exit(1)
        port_forwarding = [Port_forwarding_spec(local_vault_port, config['vault_host'], config['vault_port'])]
        start_control_master(
            host=config['gw_host'],
            port=config.get('gw_port'),
            ctl_path=config['ctl_path'],
            username=config.get('gw_user'),
            port_forwarding=port_forwarding
        )
        logging.info('SSH Control master started')

    if renew_token:
        response = perform_cert_login(
            pkcs11_module_path=config['pkcs11_module_path'],
            port=local_vault_port,
            data=config.get('vault_login_data'),
            sk_pin=config.get('sk_pin')
        )
        with open(login_json_path, 'w') as f:
            json.dump(response, f)
        with open(token_path, 'w') as f:
            f.write(response['auth']['client_token'])
        copy_vault_token_to_gw(token_path, config['ctl_path'])
    
    logging.info('Starting remote session')
    start_remote_session(config['ctl_path'])
    logging.info('Remote session closed')