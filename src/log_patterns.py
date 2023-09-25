import re


process_timestamp = re.compile(r'\*\* \((?P<process>\w+):(?P<pid>\d+)\) '
                               r'(?P<hour>\d\d):(?P<mins>\d\d):(?P<secs>\d\d)\.'
                               r'(?P<microsecs>\d{6}) ')
subsystem_level = re.compile(r'\[(?P<subsystem>\w+) (?P<level>\w+)\] ')
level_without_subsystem = re.compile(r'\[\(none\) (?P<level>\w+)\] ')
filename_lineno_func_msg = re.compile(r'(?P<filename>[^:]+):(?P<lineno>\d+) -- '
                                      r'(?P<function>\w+\(\)): (?P<message>.+)')
only_message = re.compile(r'-- (?P<message>.+)')
