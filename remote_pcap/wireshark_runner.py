import logging
from time import localtime, mktime, struct_time
from typing import Dict

from .exceptions import ConvertLogLevelError, ParseMessageError
from .log_patterns import (filename_lineno_func_msg, level_without_subsystem,
                           only_message, process_timestamp, subsystem_level)
from .process_runner import ProcessRunner


class WiresharkRunner(ProcessRunner):
    def __init__(self, name, pipename):
        super().__init__(name)
        self.pipename = pipename

    @property
    def args(self):
        return ['/usr/bin/wireshark', '-k', '--log-level', 'info',
                '--interface', self.pipename]

    def handle_stdout(self, data: str):
        try:
            record = self.message_to_logrecord(data)
            self.logger.handle(record)
        except ParseMessageError:
            self.logger.debug(data)

    def handle_stderr(self, data: str):
        try:
            record = self.message_to_logrecord(data)
            self.logger.handle(record)
        except (ParseMessageError, ConvertLogLevelError):
            self.logger.error(data)

    @staticmethod
    def parse_message(data: str) -> Dict:
        parsed_message = {}
        starpos = 0
        endpos = len(data)

        if match_obj := process_timestamp.match(data[starpos:endpos]):
            parsed_message.update(match_obj.groupdict())
            starpos += match_obj.end()
        else:
            raise ParseMessageError(f'Failed to parse log message: "{data}"')

        if match_obj := subsystem_level.match(data[starpos:endpos]):
            parsed_message.update(match_obj.groupdict())
            starpos += match_obj.end()
        elif match_obj := level_without_subsystem.match(data[starpos:endpos]):
            parsed_message.update(match_obj.groupdict())
            parsed_message['subsystem'] = 'wireshark'
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

    def message_to_logrecord(self, data: str) -> logging.LogRecord:
        current = localtime()
        details = self.parse_message(data)
        record = self.logger.makeRecord(name=self.logger.name,
                                        level=self.convert_loglevel(details['level']),
                                        fn=details['filename'],
                                        lno=int(details['lineno']),
                                        msg=f'{details["subsystem"]} -- {details["message"]}',
                                        args=None,
                                        exc_info=None,
                                        func=details['function'])
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

        raise ConvertLogLevelError(f'Unknown log level: {level}')
