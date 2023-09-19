import logging
import os
from re import match
from typing import Union
from time import localtime, mktime, struct_time

from process_runner import ProcessRunner


class SSHDumpRunner(ProcessRunner):

    def __init__(self, name: str, remote_host: str, remote_port: Union[str, int], iface: str,
                 username: str, password: str, use_key: bool, pipename: str, **kwargs):
        super().__init__(name)
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
                raise Exception(f'Key file is not exits: {key_file}')
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

    def handle_stdout(self, data: str):
        record = self.message_to_logrecord(data)
        if record is not None:
            self.logger.handle(record)
        else:
            self.logger.debug(data)

    def handle_stderr(self, data: str):
        record = self.message_to_logrecord(data)
        if record is not None:
            self.logger.handle(record)
        else:
            self.logger.error(data)

    def message_to_logrecord(self, data: str) -> logging.LogRecord:
        if match_obj := match((r'\*\* \((?P<process>\w+):(?P<pid>\d+)\) '
                               r'(?P<hour>\d\d):(?P<mins>\d\d):(?P<secs>\d\d)\.(?P<microsecs>\d{6}) '
                               r'\[(?P<subsytem>\w+) (?P<level>\w+)\] '
                               r'(?P<filename>[^:]+):(?P<lineno>\d+) -- (?P<function>\w+\(\)): '
                               r'(?P<message>.+)'), data):
            details = match_obj.groupdict()
            record = self.logger.makeRecord(name=self.logger.name,
                                            level=self.convert_loglevel(details['level']),
                                            fn=details['filename'],
                                            lno=int(details['lineno']),
                                            msg=f'{details["subsytem"]} -- {details["message"]}',
                                            args=None,
                                            exc_info=None,
                                            func=details['function'])
        elif match_obj := match((r'\*\* \((?P<process>\w+):(?P<pid>\d+)\) '
                           r'(?P<hour>\d\d):(?P<mins>\d\d):(?P<secs>\d\d)\.(?P<microsecs>\d{6}) '
                           r'\[(?P<subsytem>\w+) (?P<level>\w+)\] -- (?P<message>.+)'), data):
            details = match_obj.groupdict()
            record = self.logger.makeRecord(name=self.logger.name,
                                            level=self.convert_loglevel(details['level']),
                                            fn=details['subsytem'],
                                            lno=0,
                                            msg=f'{details["subsytem"]} -- {details["message"]}',
                                            args=None,
                                            exc_info=None,
                                            func=details['subsytem'])
        else:
            record = None

        if record is not None:
            current = localtime()
            record.created = mktime(struct_time((current.tm_year,
                                                 current.tm_mon,
                                                 current.tm_mday,
                                                 int(details['hour']),
                                                 int(details['mins']),
                                                 int(details['secs']),
                                                 current.tm_wday,
                                                 current.tm_yday,
                                                 current.tm_isdst,
                                                 current.tm_zone,
                                                 current.tm_gmtoff)))
            record.msecs = int(details['microsecs']) // 1000

        return record

    @staticmethod
    def convert_loglevel(level: str) -> int:
        if level == 'NONE':
            return logging.NOTSET

        if level in ('ERROR', 'CRITICAL', 'WARNING', 'INFO', 'DEBUG'):
            return getattr(logging, level)

        if level in ('MESSAGE', 'NOISY'):
            return logging.DEBUG

        raise Exception(f'Unknown log level: {level}')
