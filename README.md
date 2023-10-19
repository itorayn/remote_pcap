# remote_pcap

Утилита для удобного удаленного захвата трафика и отображения его в одном из анализаторов (wireshark, sngrep).

## Задача
В процессе работы IT-инженера возникают ситуации когда необходимо захватить и проанализировать сетевой трафик, для этих целей существует wireshark. Также для инженеров работающих с IP-телефонией существует утилита sngrep, которая гораздо более удобна для анализа обмена сообщениями про протоколу SIP чем wireshark. Оба этих инструментов прекрасно работают в случае если необходимо захватить трафик на том-же хосте на котором они запускаются. Но зачастую возникают ситуации когда необходимо захватить трафик на одном хосте будь то роутер, сервер IP-телефонии или любой другой сервер, а произвести анализ на другом (например рабочий ПК инженера). 

## Существующий варианты решения
Далее будут показаны несколько способов как это сделать.

### Вариант 1
Запустить захват трафика с записью в файл на удаленном хосте, а затем использую один из протоколов передачи файлов скопировать на рабочий ПК, после чего на рабочем ПК открыть файл анализатором (wireshark, sngrep).

Следующие варианты хоть и отличаются друг от друга, но принцип действия у них один:
1. Подключение к удаленному хосту по ssh
2. Запуск на удаленном хосте tcpdump
3. Вывод tcpdump'a (raw пакеты) -> stdout -> ssh туннель -> pipe
4. Получение данных (raw пакеты) из pipe и передача его в stdin wireshark'a или sngrep'a

### Вариант 2
Воспользоваться встроенной функцией удаленного захвата трафика в wireshark.
Однако данный способ имеет недостатки: 
- отсутствие возможности сохранения настроек удаленного подключения, из-за чего необходимо каждый раз заново вводить такие настройки как адрес, логин, пароль,интерфейс на удаленном хосте;
- актуален только для wireshark, sngrep такой возможности не имеет;
- отсутствует возможность запуска из терминала, только через GUI wireshark'a.

### Вариант 3
Воспользоваться командой
```
ssh user@remote_host "tcpdump -U -i eth0 -w - not tcp port 22" | wireshark -i - -k -p
```
Однако данный способ также имеет недостаток:
- данный способ корректно работает только с wireshark, c sngrep `ssh user@remote_host "tcpdump -U -i eth0 -w - not tcp port 22" | sngrep -I -` он работает нестабильно так как sngrep черз stdin получает и pcap и команды управления, из за чего управление нестабильно.

### Вариант 4
Использовать sshdump (входит в состав комплектных утилит wireshark'a). 
Пример запуска:
```
mkfifo /tmp/1234
/usr/lib/x86_64-linux-gnu/wireshark/extcap/sshdump --capture --extcap-interface ssh --fifo /tmp/1234 --remote-host 127.0.0.1 --remote-port 4022 --remote-username root --remote-password "password" --remote-interface eth0 --remote-capture-command "tcpdump -i eth0 -U -w - -f not tcp port 22" & wireshark -k -i /tmp/1234
```
или
```
mkfifo /tmp/1234
/usr/lib/x86_64-linux-gnu/wireshark/extcap/sshdump --capture --extcap-interface ssh --fifo /tmp/1234 --remote-host 127.0.0.1 --remote-port 4022 --remote-username root --remote-password "password" --remote-interface eth0 --remote-capture-command "tcpdump -i eth0 -U -w - -f not tcp port 22" & sngrep -I /tmp/12345
```
Данный способ имеет два недостатка:
- необходимость предвариательного создания pipe-файла и его очистка (или создание нового) перед повторным запуском;
- итоговая длина команды.

Для решения указанной выше задачи и была создана утилита remote_pcap.py в которой исправлены недостатки существующих способов. По сути в ней автоматизируется четвёртый вариант.


## Требования
1. На локальном хосте должен быть установлен wireshark и sngrep

2. На удаленном хосте должен быть установлен tcpdump, а также должны быть предоставлены разрешения на захват трафика тому пользователю под учётными данными которого будет производиться подключение к удаленному хосту.
```
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```


## Установка
```
pip3 install -e git+https://github.com/itorayn/remote_pcap.git#egg=remote_pcap
```

## Usage
```
usage: remote_pcap [-h] -i REMOTE_IFACE -u USERNAME (-p PASSWORD | -k) [-a {wireshark,sngrep}] remote

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
remote_pcap -i lo -u user -k -a sngrep 127.0.0.1:5022
```
