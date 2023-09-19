import os

from process_runner import ProcessRunner


class SngrepRunner(ProcessRunner):
    def __init__(self, name, pipename):
        super().__init__(name)
        self.pipename = pipename

    @property
    def args(self):
        shell_pid = os.getppid()

        with open(f'/proc/{shell_pid}/status', encoding="ascii") as info:
            for line in info:
                if line.startswith('PPid:'):
                    _, _, terminal_pid = line.partition(':')
                    terminal_pid = int(terminal_pid.strip())
                    break
            else:
                raise Exception(f'Failed to parse /proc/{shell_pid}/status')

        with open(f'/proc/{terminal_pid}/status', encoding="ascii") as info:
            for line in info:
                if line.startswith('Name:'):
                    _, _, terminal_name = line.partition(':')
                    terminal_name = terminal_name.strip()
                    break
            else:
                raise Exception(f'Failed to parse /proc/{shell_pid}/status')

        if terminal_name.startswith('gnome-terminal'):
            cmd = ['gnome-terminal', '--wait', '--']
        else:
            raise Exception(f'Unknown terminal emulator: {terminal_name}')

        cmd.extend(['/usr/bin/sngrep', '--rtp' ,'--input', self.pipename])

        return cmd

    def handle_stdout(self, data: str):
        pass

    def handle_stderr(self, data: str):
        pass
