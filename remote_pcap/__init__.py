import json
import logging
from argparse import ArgumentParser
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Union

from paramiko import AutoAddPolicy, SSHClient
from paramiko.config import SSHConfig

from remote_pcap.tool_runner import ToolRunner


@contextmanager
def ssh_connection(hostname: str, port: Union[str, int],
                   user: str, password: str,
                   identityfile: str, **_kwargs) -> Generator[SSHClient, None, None]:
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    if password is not None:
        client.connect(hostname=hostname, port=int(port),
                       username=user, password=password)
    else:
        assert identityfile is not None
        client.connect(hostname=hostname, port=int(port),
                       username=user, key_filename=str(identityfile))

    yield client

    client.close()


def get_tcpdump_path(connected_client: SSHClient) -> str:
    for path in ('/usr/bin/tcpdump', '/usr/sbin/tcpdump'):
        # Check FILE exists and the user has execute (or search) access
        _, stdout, _ = connected_client.exec_command(f'test -x {path}')
        if stdout.channel.recv_exit_status() == 0:
            return path
    raise LookupError('tcpdump not found in remote host')


def get_remote_interfaces(connected_client: SSHClient) -> List[str]:
    _, stdout, _ = connected_client.exec_command('ip -json link')
    exitcode = stdout.channel.recv_exit_status()
    if exitcode != 0:
        raise RuntimeError(f'Failed to get interfaces: {exitcode=}')
    links_info = json.loads(stdout.read().decode(encoding='utf-8'))
    return [link['ifname'] for link in links_info]


def sudoers_config_is_work(connected_client: SSHClient) -> bool:
    _, stdout, _ = connected_client.exec_command('sudo tcpdump --version')
    version_info = stdout.read().decode(encoding='utf-8')
    if version_info != '' and 'tcpdump version' in version_info:
        logging.debug(f'tcpdump version in remote host: \n{version_info}')
        return True

    logging.critical('Cannot run "sudo tcpdump" without password.')
    logging.info('Please run this command in remote host: '
                 '"echo -e "${USER}\tALL=NOPASSWD: $(which tcpdump)" '
                 '| sudo tee /etc/sudoers.d/tcpdump"')
    return False


def run_tool_runner():
    logging.basicConfig(level=logging.DEBUG, format=('%(asctime)s %(name)s %(levelname)s '
                                                     '%(filename)s:%(lineno)d %(message)s'))
    parser = ArgumentParser(description='Remote capture network trafic')
    parser.add_argument('remote', type=str, metavar='REMOTE HOST', help='Capture in host address')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Capture in interface')
    parser.add_argument('-u', '--user', type=str, help='Username for login')
    parser.add_argument('-p', '--password', type=str, help='Password for login')
    parser.add_argument('-k', '--identityfile', type=str, help='File with custom private key')
    parser.add_argument('-a', '--analyzer', type=str, default='wireshark',
                        choices=['wireshark', 'sngrep'], help='Packet analyzer')
    prog_args = parser.parse_args()

    if prog_args.password is not None and prog_args.identityfile is not None:
        parser.error('argument -k/--identityfile: not allowed with argument -p/--password')

    # Prepare values from arguments
    arg_vals = {}
    if ':' in prog_args.remote:
        arg_vals['hostname'], arg_vals['port'] = prog_args.remote.split(':')
    else:
        arg_vals['hostname'] = prog_args.remote
    arg_vals['user'] = prog_args.user
    arg_vals['password'] = prog_args.password
    arg_vals['identityfile'] = prog_args.identityfile

    ssh_dir = Path('~/.ssh/').expanduser()

    # Prepare values from ssh config
    cfg_vals = {}
    ssh_config = SSHConfig.from_path(ssh_dir.joinpath('config'))
    if prog_args.remote in ssh_config.get_hostnames():
        logging.info('Found host in user SSH config file')
        host_config = ssh_config.lookup(prog_args.remote)
        for key in ('hostname', 'port', 'user', 'identityfile'):
            cfg_vals[key] = host_config.get(key)
        if isinstance(cfg_vals['identityfile'], list):
            cfg_vals['identityfile'] = cfg_vals['identityfile'][0]

    # Prepare default values
    default_vals = {
        'port': 22,
        'identityfile': next(filter(lambda fp: fp.name in ('id_rsa', 'id_dsa',
                                                           'id_ecdsa', 'id_ed25519'),
                                    ssh_dir.iterdir()), None)
    }

    # Prepare result values
    result_kwargs = {
        'interface': prog_args.interface,
        'analyzer': prog_args.analyzer,
        'hostname': cfg_vals.get('hostname') or arg_vals.get('hostname')
    }
    for key in ('port', 'user', 'password', 'identityfile'):
        result_kwargs[key] = arg_vals.get(key) or cfg_vals.get(key) or default_vals.get(key)

    if result_kwargs['user'] is None:
        parser.error('the following arguments are required: -u/--user')

    if result_kwargs['password'] is None and result_kwargs['identityfile'] is None:
        parser.error('the following arguments are required: -p/--password or -k/--identityfile')

    logging.info(f'Result values: {result_kwargs}')

    with ssh_connection(**result_kwargs) as connected_client:
        result_kwargs['tcpdump_path'] = get_tcpdump_path(connected_client)

        if not sudoers_config_is_work(connected_client):
            raise RuntimeError('Cannot run "sudo tcpdump" without password')

        remote_interface = result_kwargs['interface']
        available_interfaces = get_remote_interfaces(connected_client)
        if remote_interface not in available_interfaces:
            raise RuntimeError(f'Interface "{remote_interface}" not found '
                               f'in remote host, {available_interfaces=}')

    logging.debug(f'Result kwargs: {result_kwargs}')

    runner = ToolRunner('main_runner', **result_kwargs)
    runner.start()
    runner.join()


if __name__ == '__main__':
    run_tool_runner()
