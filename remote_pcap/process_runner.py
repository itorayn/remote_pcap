import logging
from abc import ABC, abstractmethod
from subprocess import Popen, DEVNULL, PIPE, TimeoutExpired

from .buffer_reader import BufferReader
from .exceptions import StopError


class ProcessRunner(ABC):

    def __init__(self, name):
        self.name = name
        self.logger = logging.getLogger(self.name)
        self.process = None
        self.out_reader = None
        self.error_reader = None

    @abstractmethod
    def handle_stdout(self, data: str):
        pass

    @abstractmethod
    def handle_stderr(self, data: str):
        pass

    @property
    @abstractmethod
    def args(self):
        pass

    def run(self):
        self.logger.info('Starting ...')
        # pylint: disable-next=consider-using-with
        self.process = Popen(self.args, stdin=DEVNULL, stdout=PIPE, stderr=PIPE)
        self.out_reader = BufferReader(name=f'{self.name}.stdout_reader',
                                       buffer=self.process.stdout,
                                       data_handler=self.handle_stdout)
        self.out_reader.start()
        self.error_reader = BufferReader(name=f'{self.name}.error_reader',
                                         buffer=self.process.stderr,
                                         data_handler=self.handle_stderr)
        self.error_reader.start()

    def stop(self):
        if self.returncode is not None:
            return

        self.logger.info('Stoping ...')

        pid = self.process.pid
        for sig_name, sig_number in (('SIGUSR1', 10), ('SIGTERM', 15), ('SIGKILL', 9)):
            self.logger.info(f'Sending {sig_name} to process with pid {pid}')
            self.process.send_signal(sig_number)

            returncode = self.process.wait(timeout=1)
            if returncode is not None:
                self.logger.info(f'Process with pid {pid} was stopped by exitcode {returncode}')
                break
        else:
            self.logger.error(f'Failed to stop process with pid {pid}')
            raise StopError(f'Failed to stop process with pid {pid}')

        if self.out_reader.is_alive():
            self.out_reader.stop()

        if self.error_reader.is_alive():
            self.error_reader.stop()

    @property
    def returncode(self):
        try:
            return self.process.wait(0.1)
        except TimeoutExpired:
            return None
