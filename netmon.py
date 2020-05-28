#!/usr/bin/python3
import sys
import re
import time
import csv
import signal
import threading
import subprocess

# 统计间隔
STAT_DURATION = 10

PORTS_RATE = dict()

line_regex = re.compile(r'^IP\s+\d+\.\d+\.\d+\.\d+\.(\d+)\s+>\s+\d+\.\d+\.\d+\.\d+\.(\d+):.*tcp\s+(\d+)$')

def save_csv():
    print('save csv')
    header = []
    with open('netmon.csv', 'w') as f:
        f_csv = csv.writer(f)
        for key in PORTS_RATE:
            if len(header) == 0:
                # 构造csv表头
                header.append('Port')
                for i in range(0, len(PORTS_RATE[key])):
                    header.append(str((i + 1) * 10) + 's')
                f_csv.writerow(header)
            # 构造数据
            row = []
            row.append('port-' + key)
            row.extend(PORTS_RATE[key])
            f_csv.writerow(row)

# 自定义信号处理函数
def my_handler(signum, frame):
    print('receive signal: ' + str(signum))
    save_csv()
    exit(0)
 
 
# 设置相应信号处理的handler
signal.signal(signal.SIGINT, my_handler)
signal.signal(signal.SIGHUP, my_handler)
signal.signal(signal.SIGTERM, my_handler)


def make_command(ports):
    port_str = 'or'.join(ports)
    return 'tcpdump -i any -nn -t -q ' + port_str + ''

def parse_line(line):
    ret = re.findall(line_regex, line)
    if ret == None or len(ret) != 1:
        return None
    (src, dst, length) = ret[0]
    return (src, dst, int(length))

def format_speed(speed):
    return str(round(speed/1024, 2))

def output_speed(ports_stat):
    history_stats = dict()
    for key in ports_stat:
        history_stats[key] = ports_stat[key]
    while True:
        time.sleep(STAT_DURATION)
        speeds = []
        for key in ports_stat:
            transfer_bytes = ports_stat[key] - history_stats[key]
            item = {
                'port': key,
                'bytes': transfer_bytes
            }
            speeds.append(item)
        speeds.sort(key=lambda element: element['bytes'], reverse=True)
        for speed in speeds:
            PORTS_RATE[speed['port']].append(format_speed(speed['bytes']))
        # 备份当前数据
        for key in ports_stat:
            history_stats[key] = ports_stat[key]


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print('please set port')
        sys.exit(-1)

    ports = []

    # 端口收发统计
    ports_stat = dict()
    # 获取端口列表
    for i in range(1, len(sys.argv)):
        port = int(sys.argv[i])
        if port <= 0 or port >= 65536:
            print('port error: ' + sys.argv[i])
            exit(-1)
        print('add port: ' + sys.argv[i])
        ports_stat[sys.argv[i]] = 0
        PORTS_RATE[sys.argv[i]] = []
        ports.append(' port ' + sys.argv[i] + ' ')
    
    command = make_command(ports)
    tcpdump = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, close_fds=True)
    if not tcpdump:
        raise Exception('cannot execute command')
    output = threading.Thread(target=output_speed, args=(ports_stat,))
    output.setDaemon(True)
    output.start()
    while True:
        # 按行读取测试工具输出
        data = tcpdump.stdout.readline()
        if data and len(data) > 0:
            line = str(data, encoding='utf8')
            ret = parse_line(line)
            if ret != None:
                (src, dst, length) = ret
                if src in ports_stat:
                    ports_stat[src] = ports_stat[src] + length
                elif dst in ports_stat:
                    ports_stat[dst] = ports_stat[dst] + length
    
