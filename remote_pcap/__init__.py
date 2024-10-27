import logging
from argparse import ArgumentParser
from pathlib import Path

from paramiko.config import SSHConfig

from .tool_runner import ToolRunner


def run_tool_runner():
    logging.basicConfig(level=logging.DEBUG, format=('%(asctime)s %(name)s %(levelname)s '
                                                     '%(filename)s:%(lineno)d %(message)s'))
    parser = ArgumentParser(description='Remote capture network trafic')
    parser.add_argument('remote', type=str, metavar='REMOTE HOST', help='Capture in host address')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Capture in interface')
    parser.add_argument('-u', '--user', type=str, help='Username for login')
    parser.add_argument('-p', '--password', type=str, help='Password for login')
    parser.add_argument('-k', '--use-key', action='store_true', help='Use public key')
    parser.add_argument('-kf', '--identityfile', type=str, help='File with custom private key')
    parser.add_argument('-a', '--analyzer', type=str, default='wireshark',
                        choices=['wireshark', 'sngrep'], help='Packet analyzer')
    prog_args = parser.parse_args()

    if prog_args.password is not None and prog_args.use_key is True:
        parser.error('argument -k/--use-key: not allowed with argument -p/--password')

    ssh_dir = Path('~/.ssh/').expanduser()

    # Prepare default value
    default_vals = {
        'port': 22,
        'identityfile': next(filter(lambda fp: fp.name in ('id_rsa', 'id_dsa',
                                                           'id_ecdsa', 'id_ed25519'),
                                    ssh_dir.iterdir()), None)
    }

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

    # Prepare values from arguments
    arg_vals = {}
    if ':' in prog_args.remote:
        arg_vals['hostname'], arg_vals['port'] = prog_args.remote.split(':')
    else:
        arg_vals['hostname'] = prog_args.remote
    arg_vals['user'] = prog_args.user
    arg_vals['password'] = prog_args.password
    arg_vals['identityfile'] = prog_args.identityfile

    result_kwargs = {
        'interface': prog_args.interface,
        'analyzer': prog_args.analyzer
    }
    for key in ('hostname', 'port', 'user', 'password', 'identityfile'):
        result_kwargs[key] = cfg_vals.get(key) or arg_vals.get(key) or default_vals.get(key)

    if result_kwargs['user'] is None:
        parser.error('the following arguments are required: -u/--user')

    if result_kwargs['password'] is None and result_kwargs['identityfile'] is None:
        parser.error('the following arguments are required: -p/--password or -k/--identityfile')

    logging.debug(f'Result kwargs: {result_kwargs}')
    runner = ToolRunner('main_runner', **result_kwargs)
    runner.start()
    runner.join()


if __name__ == '__main__':
    run_tool_runner()
