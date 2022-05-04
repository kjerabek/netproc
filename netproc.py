import psutil
import time


class ProcConExtractor:
    proc_info_collection = {}

    def __init__(self, file_name: str, stop_count: int = -1, dump_freq: int = 10, sleep_time: float = 0.1):
        self.csv_file = open(file_name, 'w+')
        self.current_time = None
        self.header_written = False
        self.dump_finished_freq = dump_freq
        self.stop_count = stop_count
        self.stop_condition = True if stop_count == -1 else False
        self.sleep_time = sleep_time

    @staticmethod
    def get_flowkey(src_ip: str, dst_ip: str,
                    sport: int, dport: int, proto: str) -> str:
        if src_ip == dst_ip:
            first_ip, second_ip = src_ip, dst_ip
            if sport < dport:
                first_port, second_port = sport, dport
            else:
                first_port, second_port = dport, sport
        elif src_ip < dst_ip:
            first_ip, second_ip = src_ip, dst_ip
            first_port, second_port = sport, dport
        else:
            first_ip, second_ip = dst_ip, src_ip
            first_port, second_port = dport, sport

        return f'{first_ip}-{second_ip}_{first_port}-{second_port}_{proto}'

    def set_current_time(self):
        self.current_time = int(time.time() * 1000000)

    def run(self):
        counter = 0

        while counter != self.stop_count or self.stop_condition:
            self.set_current_time()

            for process in psutil.process_iter(attrs=['connections', 'pid', 'cmdline', 'username', 'name']):
                try:
                    proc_info = process.info

                    if proc_info['connections'] is not None and len(proc_info['connections']) > 0:
                        for connection in proc_info['connections']:
                            if connection.status not in [psutil.CONN_NONE, psutil.CONN_LISTEN]:
                                flow_key = ProcConExtractor.get_flowkey(connection.laddr[0],
                                                                        connection.raddr[0],
                                                                        connection.laddr[1],
                                                                        connection.raddr[1],
                                                                        'TCP')

                                if flow_key in self.proc_info_collection.keys():
                                    self.proc_info_collection[flow_key]['last_seen'] = self.current_time
                                else:
                                    proc_record = dict(flow_key=flow_key,
                                                       name=proc_info['name'],
                                                       first_seen=self.current_time,
                                                       last_seen=self.current_time,
                                                       cmdline=proc_info['cmdline'],
                                                       pid=proc_info['pid'],
                                                       )

                                    self.proc_info_collection[flow_key] = proc_record
                except psutil.NoSuchProcess:
                    pass  # do not process non-existent process

            if not counter % self.dump_finished_freq:
                self.write_finished()

            time.sleep(self.sleep_time)
            counter += 1

    def write_csv_header(self):
        if len(self.proc_info_collection.keys()) == 0:
            return

        header = ','.join(list(self.proc_info_collection.values())[0].keys())
        self.csv_file.write(header + '\n')
        self.header_written = True

    def write_finished(self):
        if not self.header_written:
            self.write_csv_header()

        for key in list(self.proc_info_collection.keys()):
            if self.proc_info_collection[key]['last_seen'] != self.current_time:
                self.csv_file.write(','.join([str(value) for value in self.proc_info_collection[key].values()])+'\n')
                del self.proc_info_collection[key]

    def __del__(self):
        self.set_current_time()
        self.write_finished()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Monitor and dump connections with IP mapping to processes they belong. Only unique connections.')

    parser.add_argument('output',
                        type=str,
                        help='Name and path for output csv file.')
    parser.add_argument('--stop-iteration',
                        type=int,
                        default=-1,
                        help='How many iterations will proceed until stopped, -1 for infinite. (default=-1)')
    parser.add_argument('--dump-freq',
                        type=int,
                        default=10,
                        help='After how many iterations dump finished connections to csv. (default=10)')
    parser.add_argument('--sleep-time',
                        type=float,
                        default=0.1,
                        help='Sleep time after each monitoring iteration.')

    parsed_args = parser.parse_args()

    proc_con_extractor = ProcConExtractor(parsed_args.output,
                                          parsed_args.stop_iteration,
                                          parsed_args.dump_freq,
                                          parsed_args.sleep_time)
    proc_con_extractor.run()
