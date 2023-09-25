# remote_pcap

Утилита для удобного удаленного захвава траффика и отображение его в одном из анализаторов (wireshark, sngrep).


## usage
```
usage: remote_pcap.py [-h] -i REMOTE_IFACE -u USERNAME (-p PASSWORD | -k) [-a {wireshark,sngrep}] remote

Videos to images

positional arguments:
  remote                Capture in host address

options:
  -h, --help            show this help message and exit
  -i REMOTE_IFACE, --interface REMOTE_IFACE
                        Capture in interface
  -u USERNAME, --username USERNAME
                        Username for login
  -p PASSWORD, --password PASSWORD
                        Password for login
  -k, --use-key         Use public key
  -a {wireshark,sngrep}, --analyzer {wireshark,sngrep}
                        Packet analyzer
```


## Пример запуска
```
python3 remote_pcap.py -i lo -u user -k -a sngrep 127.0.0.1:5022
```
