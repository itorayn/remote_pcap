import os
from pathlib import Path
from typing import Dict, Optional, Union

from .exceptions import ParseMessageError
from .log_patterns import (filename_lineno_func_msg, only_message,
                           process_timestamp, subsystem_level)
from .wireshark_runner import WiresharkRunner


class SSHDumpRunner(WiresharkRunner):

    def __init__(self, name: str, pipename: str,
                 hostname: str, port: Union[str, int],
                 interface: str, user: str, password: Optional[str] = None,
                 identityfile: Optional[Union[Path, str]] = None,
                 tcpdump_path: str = '/usr/bin/tcpdump'):
        super(WiresharkRunner, self).__init__(name)
        self.pipename = pipename
        self.hostname = hostname
        self.port = port

        self.user = user
        self.tcpdump_path = tcpdump_path
        self.interface = interface
        if identityfile is None:
            if password is None:
                raise AttributeError('Public key or password is not set!')
        elif not os.path.exists(identityfile):
            raise FileNotFoundError(f'Key file is not exits: {identityfile}')
        self.password = password
        self.identityfile = identityfile

    @property
    def args(self):
        cmd = ['/usr/lib/x86_64-linux-gnu/wireshark/extcap/sshdump', '--capture',
               '--log-level', 'debug',
               '--extcap-interface', 'ssh', '--fifo', self.pipename,
               '--remote-host', self.hostname, '--remote-port', str(self.port),
               '--remote-username', self.user]
        if self.identityfile:
            cmd.extend(['--sshkey', self.identityfile])
        else:
            cmd.extend(['--remote-password', self.password])
        cmd.extend(['--remote-capture-command',
                    f'sudo {self.tcpdump_path} -i {self.interface} -U -w - -f not tcp port 22'])
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
