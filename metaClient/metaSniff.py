from scapy.all import *
from websocket import create_connection
from multiprocessing import Process
import config as config
import shutil
import threataggregator as tag

IPRepDB = []
DNSRepDB = []
UniqueConns = {}

ws = create_connection(config.WS_SERVER)


def chkIPRepDB(pkt):
    if (pkt[IP].src in IPRepDB) or (pkt[IP].dst in IPRepDB):
        alert(pkt)
    return


def chkDNSRepDB(dns):
    return


def logToDB(data):
    return


def alert(indicator):
    # print "Alert..."
    # indicator.show()
    alert = dict(
        consumer_key = config.CONSUMER_KEY,
        packet = indicator,
        datatype = "alert",
        details = "Known Bad IP Address"
    )
    p = Process(target=logger, args=(alert,))
    p.start()
    return


def init():
    try:
        shutil.rmtree("./.cache/")
        _db_add = []
        _db_del = []
        _db_equal = []
        tag.start(tag.feeds, _db_add, _db_del, _db_equal)
        tag.process(_db_add, _db_del, _db_equal)

        fd = open(".cache/IPRepDB", "r")
        lines = fd.readlines()
        for line in lines:
            if line not in IPRepDB:
                IPRepDB.append(line.strip())
        fd.close()
        print len(IPRepDB), "IP Addresses loaded"
        # print IPRepDB[100]
        print "Monitoring interface", config.MON_IFACE
    except Exception, e:
        print str(e)
        return


def logger(evt):
    try:
        ws.send(str(evt))
    except Exception, e:
        print str(e)
        pass


def pkt_callback(pkt):
    try:
        # pkt.show() # debug statement
        packet_meta_data = {}
        packet_meta_data['consumer_key'] = config.CONSUMER_KEY
        if IP in pkt:
            packet_meta_data['src_ip'] = pkt[IP].src
            packet_meta_data['dest_ip'] = pkt[IP].dst
            if (pkt[IP].src == config.WS_SERVER_IP) or (pkt[IP].dst == config.WS_SERVER_IP):
                return
            chk1 = Process(target=chkIPRepDB, args=(pkt,))
            chk1.start()
        if IPv6 in pkt:
            packet_meta_data['src_ip'] = pkt[IPv6].src
            packet_meta_data['dest_ip'] = pkt[IPv6].dst
        if UDP in pkt:
            packet_meta_data['proto'] = "UDP"
            packet_meta_data['src_port'] = pkt[UDP].sport
            packet_meta_data['dest_port'] = pkt[UDP].dport
            if pkt.haslayer(DNS):
                packet_meta_data['DNS'] = pkt[DNS]
        if TCP in pkt:
            packet_meta_data['proto'] = "TCP"
            packet_meta_data['src_port'] = pkt[TCP].sport
            packet_meta_data['dest_port'] = pkt[TCP].dport
        if ARP in pkt:
            packet_meta_data['proto'] = "ARP"
            packet_meta_data['op'] = pkt[ARP].op
            packet_meta_data['hwsrc'] = pkt[ARP].hwsrc
            packet_meta_data['psrc'] = pkt[ARP].psrc
            packet_meta_data['hwdst'] = pkt[ARP].hwdst
            packet_meta_data['pdst'] = pkt[ARP].pdst
        if ICMP in pkt:
            packet_meta_data['proto'] = "ICMP"
            packet_meta_data['icmp_type'] = pkt[ICMP].type
            packet_meta_data['icmp_code'] = pkt[ICMP].code
        if LLC in pkt:
            return
        if packet_meta_data == {}:
            pkt.show()
        if packet_meta_data != {}:
            pass
            # logger(packet_meta_data)
            # p = Process(target=logger, args=(packet_meta_data,))
            # p.start()
            # p.join()
    except Exception, e:
        pkt.show()
        pass


def main():
    init()
    sniff(iface=config.MON_IFACE, prn=pkt_callback, filter="", store=0)
# sniff(iface="<Interface>", prn = lambda x: x.show(), filter="tcp", store=0)


main()
