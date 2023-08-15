import logging
from re import match
from time import localtime, mktime, struct_time

from process_runner import ProcessRunner


class WiresharkRunner(ProcessRunner):
    def __init__(self, name, pipename):
        super().__init__(name)
        self.pipename = pipename

    @property
    def args(self):
        return ['/usr/bin/wireshark', '-k', '--log-level', 'info',
                '--interface', self.pipename]

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
                                 r'\[\(none\) (?P<level>\w+)\] '
                                 r'(?P<filename>[^:]+):(?P<lineno>\d+) -- (?P<function>\w+\(\)): '
                                 r'(?P<message>.+)'), data):
            details = match_obj.groupdict()
            record = self.logger.makeRecord(name=self.logger.name,
                                            level=self.convert_loglevel(details['level']),
                                            fn=details['filename'],
                                            lno=int(details['lineno']),
                                            msg=details['message'],
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
