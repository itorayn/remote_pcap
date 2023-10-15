import logging
from threading import Thread, Event

from .sshdump_runner import SSHDumpRunner
from .wireshark_runner import WiresharkRunner
from .sngrep_runner import SngrepRunner
from .pipe_manager import Pipe


class ToolRunner(Thread):
    def __init__(self, name, args):
        Thread.__init__(self, name=name, daemon=True)
        self.logger = logging.getLogger(self.name)
        self.args = args
        self._need_stop = Event()
        self.dumper = None
        self.analyzer = None

    def run(self):
        self.logger.info('Starting ...')

        with Pipe() as fifo_path:
            self.dumper = SSHDumpRunner('dumper',
                                        remote_host=self.args.remote_host,
                                        remote_port=self.args.remote_port,
                                        iface=self.args.remote_iface,
                                        username=self.args.username,
                                        password=self.args.password,
                                        use_key=self.args.use_key,
                                        pipename=fifo_path)
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
