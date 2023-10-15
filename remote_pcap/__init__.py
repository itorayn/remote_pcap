import logging
from argparse import ArgumentParser

from .tool_runner import ToolRunner


def run_tool_runner():
    logging.basicConfig(level=logging.DEBUG, format=('%(asctime)s %(name)s %(levelname)s '
                                                     '%(filename)s:%(lineno)d %(message)s'))
    parser = ArgumentParser(description='Videos to images')
    parser.add_argument('remote', type=str, help='Capture in host address')
    parser.add_argument('-i', '--interface', type=str,  dest='remote_iface',
                        required=True, help='Capture in interface')
    parser.add_argument('-u', '--username', type=str, dest='username',
                        required=True, help='Username for login')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--password',
                       type=str, dest='password', help='Password for login')
    group.add_argument('-k', '--use-key', action='store_true',
                       dest='use_key', help='Use public key')
    parser.add_argument('-a', '--analyzer', type=str, dest='analyzer', default='wireshark',
                        choices=['wireshark', 'sngrep'], help='Packet analyzer')
    prog_args = parser.parse_args()
    if ':' in prog_args.remote:
        prog_args.remote_host, prog_args.remote_port = prog_args.remote.split(':')
    else:
        prog_args.remote_host = prog_args.remote
        prog_args.remote_port = 22

    runner = ToolRunner('MainRunner', prog_args)
    runner.start()
    runner.join()


if __name__ == '__main__':
    run_tool_runner()
