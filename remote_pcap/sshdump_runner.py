import os
from pathlib import Path
from typing import Dict, Union

from .exceptions import ParseMessageError
from .log_patterns import (filename_lineno_func_msg, only_message,
                           process_timestamp, subsystem_level)
from .wireshark_runner import WiresharkRunner


class SSHDumpRunner(WiresharkRunner):

    def __init__(self, name: str, pipename: str,
                 remote_host: str, remote_port: Union[str, int],
                 iface: str, username: str, password: str = None,
                 key_file: Union[Path, str] = None):
        super(WiresharkRunner, self).__init__(name)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.iface = iface
        self.username = username

        if key_file is None:
            if password is None:
                raise AttributeError('Public key or password is not set!')
        elif not os.path.exists(key_file):
            raise FileNotFoundError(f'Key file is not exits: {key_file}')

        self.password = password
        self.key_file = key_file
        self.pipename = pipename

    @property
    def args(self):
        cmd = ['/usr/lib/x86_64-linux-gnu/wireshark/extcap/sshdump', '--capture',
               '--log-level', 'debug',
               '--extcap-interface', 'ssh', '--fifo', self.pipename,
               '--remote-interface', self.iface, '--remote-host', self.remote_host,
               '--remote-port', str(self.remote_port), '--remote-username', self.username]
        if self.key_file:
            cmd.extend(['--sshkey', self.key_file])
        else:
            cmd.extend(['--remote-password', self.password])
        cmd.extend(['--remote-capture-command',
                    f'/usr/bin/tcpdump -i {self.iface} -U -w - -f not tcp port 22'])
        return cmd

    @staticmethod
    def parse_message(data: str) -> Dict:
        parsed_message = {}
        starpos = 0
        endpos = len(data)

        for pattern in (process_timestamp, subsystem_level):
            if match_obj := pattern.match(data[starpos:endpos]):
                parsed_message.update(match_obj.groupdict())
                starpos += match_obj.end()
            else:
                raise ParseMessageError(f'Failed to parse log message: "{data}"')

        if match_obj := filename_lineno_func_msg.match(data[starpos:endpos]):
            parsed_message.update(match_obj.groupdict())
        elif match_obj := only_message.match(data[starpos:endpos]):
            parsed_message.update(match_obj.groupdict())
            parsed_message.update({'filename': parsed_message['subsystem'],
                                   'lineno': 0,
                                   'function': parsed_message['subsystem']})
        else:
            raise ParseMessageError(f'Failed to parse log message: "{data}"')
        return parsed_message
