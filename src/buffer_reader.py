import logging
import select
from threading import Thread


class BufferReader(Thread):

    def __init__(self, name: str, buffer, data_handler=None):
        Thread.__init__(self, name=name, daemon=True)
        self.logger = logging.getLogger(self.name)
        self.buffer = buffer
        self._need_stop = False
        if callable(data_handler):
            self._data_handler = data_handler
        else:
            self._data_handler = None

    def run(self):
        self.logger.info('Starting ...')
        file_descriptor = self.buffer.fileno()
        epoll = select.epoll()
        epoll.register(file_descriptor, select.EPOLLIN | select.EPOLLHUP)

        while self._need_stop is False:
            for fileno, event in epoll.poll(1):
                if fileno != file_descriptor:
                    self.logger.error(f'Recived epoll data with unknown file descriptor {fileno}')
                    continue
                if event & select.EPOLLIN:
                    while True:
                        data = self.buffer.readline()
                        if data == b'':
                            break
                        if callable(self._data_handler):
                            self._data_handler(data.decode(encoding='utf8').strip(' \n'))
                elif event & select.EPOLLHUP:
                    self.logger.info('Recive End-Of-Steam, terminate buffer reader')
                    self._need_stop = True
                    continue
                else:
                    self.logger.error(f'Recived epoll data with unknown event {event}')
                    continue

        epoll.unregister(file_descriptor)
        epoll.close()

    def stop(self):
        if self.is_alive():
            self.logger.info('Stoping ...')
            self._need_stop = True
