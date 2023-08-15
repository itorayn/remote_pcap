from os import listdir, mkfifo, remove
from random import choices
from string import ascii_lowercase


class Pipe():
    def __init__(self, tmp_dir: str = '/tmp/'):
        while True:
            fifo_name = 'pipe_' + ''.join(choices(ascii_lowercase, k=5))
            if fifo_name not in listdir(path=tmp_dir):
                break
        self.fifo_path = tmp_dir + fifo_name

    def __enter__(self) -> str:
        mkfifo(self.fifo_path)
        return self.fifo_path

    def __exit__(self, type, value, traceback):
        remove(self.fifo_path)
