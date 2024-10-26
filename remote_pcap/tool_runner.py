import logging
import os
from pathlib import Path
from threading import Event, Thread

from .pipe_manager import Pipe
from .sngrep_runner import SngrepRunner
from .sshdump_runner import SSHDumpRunner
from .wireshark_runner import WiresharkRunner


class ToolRunner(Thread):
    def __init__(self, name: str, args):
        Thread.__init__(self, name=name, daemon=True)
        self.logger = logging.getLogger(self.name)
        self.args = args
        self._need_stop = Event()
        self.dumper = None
        self.analyzer = None

    def run(self):
        self.logger.info('Starting ...')

        ssh_dump_kwargs = {
            'remote_host': self.args.remote_host,
            'remote_port': self.args.remote_port,
            'iface': self.args.remote_iface,
            'username': self.args.username
        }

        if self.args.use_key:
            if self.args.key_file is None:
                ssh_dir = Path(f'{os.getenv("HOME")}/.ssh')
                keys = filter(lambda fp: fp.name.startswith('id_') and not fp.name.endswith('.pub'),
                              ssh_dir.iterdir())
                selected_key = next(keys, None)
                if selected_key is None:
                    raise LookupError(f'Private key not found in "{str(ssh_dir)}"')
            else:
                selected_key = self.args.key_file
            self.logger.info(f'Using private key: {selected_key}')
            ssh_dump_kwargs['key_file'] = selected_key
        else:
            ssh_dump_kwargs['password'] = self.args.password

        with Pipe() as fifo_path:
            self.dumper = SSHDumpRunner('dumper', pipename=fifo_path, **ssh_dump_kwargs)
            self.dumper.run()

            if self.args.analyzer == 'wireshark':
                self.analyzer = WiresharkRunner('wireshark', pipename=fifo_path)
            elif self.args.analyzer == 'sngrep':
                self.analyzer = SngrepRunner('sngrep', pipename=fifo_path)
            else:
                raise AttributeError(f'Unknown packet analyzer: {self.args.analyzer}')
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
