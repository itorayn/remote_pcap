import logging
from pathlib import Path
from threading import Event, Thread
from typing import Union

from .pipe_manager import Pipe
from .sngrep_runner import SngrepRunner
from .sshdump_runner import SSHDumpRunner
from .wireshark_runner import WiresharkRunner


class ToolRunner(Thread):
    def __init__(self, name: str, hostname: str, port: Union[str, int], user: str, password: str,
                 identityfile: Union[Path, str], interface: str, analyzer: str,
                 tcpdump_path: str = '/usr/bin/tcpdump'):
        Thread.__init__(self, name=name, daemon=True)
        self.logger = logging.getLogger(name)
        self.ssh_dump_kwargs = {
            'hostname': hostname,
            'port': port,
            'user': user,
            'tcpdump_path': tcpdump_path,
            'interface': interface
        }
        if password is not None:
            self.ssh_dump_kwargs['password'] = password
        elif identityfile is not None:
            self.ssh_dump_kwargs['identityfile'] = identityfile
        else:
            raise AttributeError('Public key or password is not set!')

        self.analyzer_type = analyzer

        self._need_stop = Event()
        self.dumper = None
        self.analyzer = None

    def run(self):
        self.logger.info('Starting ...')

        with Pipe() as fifo_path:
            self.dumper = SSHDumpRunner('dumper', pipename=fifo_path, **self.ssh_dump_kwargs)
            self.dumper.run()

            if self.analyzer_type == 'wireshark':
                self.analyzer = WiresharkRunner('wireshark', pipename=fifo_path)
            elif self.analyzer_type == 'sngrep':
                self.analyzer = SngrepRunner('sngrep', pipename=fifo_path)
            else:
                raise AttributeError(f'Unknown packet analyzer: {self.analyzer_type}')
            self.analyzer.run()

            while self._need_stop.wait(1) is False:
                if self.dumper.returncode is not None:
                    self.stop()
                if self.analyzer.returncode is not None:
                    self.stop()
            self.dumper.stop()
            # self.analyzer.stop()

    def stop(self):
        self.logger.info('Stoping ...')
        self._need_stop.set()
