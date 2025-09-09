from scapy.all import *


class CovertTarget:

    def __init__(self, target_ip, proto):
        self.target_ip = target_ip
        self.proto = proto

    def check_connection(self):
        if self.proto == "ICMP":
            r = sr1(IP(dst=self.target_ip) / ICMP(), timeout=2)
            if r is None:
                print(f"Target is not responding to {self.proto}")
                return 1
            else:
                return 0

    def check_receiver(self):
    # TODO: send health check
        packet_to_send = 


def main():
    x = CovertTarget("10.1.1.1", "ICMP")
    can_recieve_packet = x.check_connection()
    if can_recieve_packet == 1:
        return
    has_receiver_running = x.check_receiver()


main()
