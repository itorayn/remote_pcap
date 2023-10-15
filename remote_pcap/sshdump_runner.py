import os
from typing import Union, Dict

from .exceptions import ParseMessageError
from .wireshark_runner import WiresharkRunner
from .log_patterns import process_timestamp, subsystem_level, filename_lineno_func_msg, only_message


class SSHDumpRunner(WiresharkRunner):

    def __init__(self, name: str, remote_host: str, remote_port: Union[str, int], iface: str,
                 username: str, password: str, use_key: bool, pipename: str):
        super(WiresharkRunner, self).__init__(name)
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.iface = iface
        self.username = username
        self.password = password
        self.use_key = use_key
        if self.use_key:
            key_file = f'{os.getenv("HOME")}/.ssh/id_rsa.pub'
            if os.path.exists(key_file):
                self.key_file = key_file
            else:
                raise FileNotFoundError(f'Key file is not exits: {key_file}')
        self.pipename = pipename

    @property
    def args(self):
        cmd = ['/usr/lib/x86_64-linux-gnu/wireshark/extcap/sshdump', '--capture',
               '--log-level', 'debug',
               '--extcap-interface', 'ssh', '--fifo', self.pipename,
               '--remote-interface', self.iface, '--remote-host', self.remote_host,
               '--remote-port', self.remote_port, '--remote-username', self.username]
        if self.use_key:
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
