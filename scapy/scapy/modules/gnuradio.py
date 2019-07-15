## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

"""
Gnuradio layers, sockets and send/receive functions.
"""

import socket, struct
from scapy.config import conf
from scapy.data import MTU
from scapy.packet import *
from scapy.fields import *
from scapy.supersocket import SuperSocket
from scapy import sendrecv
from scapy import main
import atexit
import scapy.layers.gnuradio
from scapy.layers.dot15d4 import *
import os
import sys
import subprocess

class GnuradioSocket(SuperSocket):
    desc = "read/write packets on a UDP Gnuradio socket"

    def __init__(self, peer="127.0.0.1"):
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.tx_addr = (peer, 52001)
        self.rx_addr = (peer, 52002)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        self.ins.bind(self.rx_addr)

    def recv(self, x=MTU):
        data, addr = self.ins.recvfrom(x)
        p = scapy.layers.gnuradio.GnuradioPacket(data)
        return p

    def send(self, pkt, number=None):
        if not pkt.haslayer(scapy.layers.gnuradio.GnuradioPacket):
            pkt = scapy.layers.gnuradio.GnuradioPacket()/pkt
        if number is not None:
            print('Sending Packet #{0}: {1}'.format(number, pkt.payload.summary()))
        else:
            print('Sending Packet: {}'.format(pkt.payload.summary()))
        if isinstance(pkt, bytes):
            sx = pkt
        else:
            sx = bytes(pkt)
        if hasattr(pkt, "sent_time"):
            pkt.sent_time = time.time()
            print('Pkt Sent Time: {}'.format(pkt.sent_time))
        self.outs.sendto(sx, self.tx_addr)

def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        yield layer
        counter += 1

def wait_for_hardware(hardware):
    if hardware == 'usrp':
        search_string = ''
    elif hardware == 'hackrf':
        search_string = 'Using HackRF'
    while True:
        out = conf.gr_process.stdout.readline().decode('utf8')
        if search_string in out:
            time.sleep(1) # wait an extra second for everything to load up
            break

@conf.commands.register
def srradio(pkts, radio=None, hardware=None, listen=True, wait_every=True, wait_timeout=0.25, ch=None, env=None, *args, **kargs):
    """send and receive using a Gnuradio socket"""
    sr_packets = []
    if radio is not None:
        if hardware == 'usrp':
            switch_radio_protocol(radio, hardware=hardware, ch=ch, env=env, mode='rf')
        elif hardware == 'hackrf':
            switch_radio_protocol(radio, hardware=hardware, ch=ch, env=env, mode='tx')
    s = GnuradioSocket()
    number = 0
    for pkt in pkts:
        number += 1
        s.send(pkt, number)
        if wait_every:
            if hardware == 'ursp':
                print('Waiting {} seconds for responses...'.format(wait_timeout))
                rv = sendrecv.sniff(opened_socket=s, timeout=wait_timeout)
                for r_pkt in rv:
                    if r_pkt != None:
                        if str(r_pkt) != str(pkt):
                            print('Received packet at {timestamp}'.format(timestamp=r_pkt.time))
                            sr_packets.append(r_pkt)
            elif hardware == 'hackrf':
                time.sleep(wait_timeout) # hackrf can't listen in between, but may want to simply wait in between
    if not wait_every and hardware != 'hackrf': # can't receive + transmit with the hackrf...could start up a new tx flowgraph but that takes too much time
        pkt_strings = [str(pkt) for pkt in pkts]
        print('Waiting {} seconds for responses...'.format(wait_timeout))
        rv = sendrecv.sniff(opened_socket=s, timeout=wait_timeout)
        for r_pkt in rv:
            if r_pkt != None:
                if str(r_pkt) not in pkt_strings: # make sure that it isn't a duplicate
                    print('Received packet at {timestamp}'.format(timestamp=r_pkt.time))
                    sr_packets.append(r_pkt)
    print('Closing socket...')
    time.sleep(2) # sleep for a couple seconds in case the socket was blocked up
    s.close()
    conf.gr_process.kill()
    return sr_packets

@conf.commands.register
def srradio1(pkts, radio=None, hardware=None, ch=None, env=None, *args, **kargs):
    """send and receive 1 packet using a Gnuradio socket"""
    a, b = srradio(pkts, radio=radio, ch=ch, env=env, *args, **kargs)
    if len(a) > 0:
        return a[0][1]

@conf.commands.register
def sniffradio(radio=None, hardware=None, ch=None, env=None, opened_socket=None, *args, **kargs):
    if radio is not None:
        switch_radio_protocol(radio, hardware=hardware, ch=ch, env=env, mode='rx')
    s = opened_socket if opened_socket is not None else GnuradioSocket()
    rv = sendrecv.sniff(opened_socket=s, *args, **kargs)
    if opened_socket is None:
        s.close()
    conf.gr_process.kill()
    return rv

def build_modulations_dict(env=None):
    hardwares = ['hackrf', 'usrp']
    for hardware in hardwares:
        hardware_dir = os.path.join(conf.gr_mods_path, hardware)
        conf.gr_modulations[hardware] = dict.fromkeys([x for x in os.listdir(hardware_dir)]) # Find what modulation folders exist
        for modulation in conf.gr_modulations[hardware]:
            conf.gr_modulations[hardware][modulation] = {} # set as empty dict one at a time to avoid references to the same dict
            for mode in os.listdir(os.path.join(hardware_dir, modulation)):
                if '_' in mode:
                    keyword = mode[mode.index('_') + 1:] # keyword example: tx, rx
                    keyword_files = os.listdir(os.path.join(hardware_dir, modulation, mode))
                    if 'top_block.py' not in keyword_files: # check if the grc has been compiled
                        try:
                            print('Compiling {0} for {1}'.format(mode, hardware))
                            outdir = "--directory=%s" % os.path.join(hardware_dir, modulation, mode) # try to compile the grc file
                            subprocess.check_call(['grcc', outdir, os.path.join(hardware_dir, modulation, mode, keyword_files[0])], env=env)
                            conf.gr_modulations[hardware][modulation][keyword] = os.path.join(hardware_dir, modulation, mode, 'top_block.py')
                        except: # if compiling the grc failed, then set this modulation keyword to None
                            conf.gr_modulations[hardware][modulation][keyword] = None
                    else:
                        conf.gr_modulations[hardware][modulation][keyword] = os.path.join(hardware_dir, modulation, mode, 'top_block.py')

def sigint_ignore():
    import os
    os.setpgrp()

@conf.commands.register
def gnuradio_set_vars(host="localhost", port=8080, **kargs):
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpc is missing to use this function.")
    else:
        s = xmlrpc.Server("http://%s:%d" % (host, port))
        for k, v in kargs.iteritems():
            try:
                getattr(s, "set_%s" % k)(v)
            except xmlrpc.Fault:
                print("Unknown variable '%s'" % k)
        s = None

@conf.commands.register
def gnuradio_get_vars(*args, **kargs):
    if "host" not in kargs:
        kargs["host"] = "127.0.0.1"
    if "port" not in kargs:
        kargs["port"] = 8080
    rv = {}
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpc is missing to use this function.")
    else:
        s = xmlrpc.Server("http://%s:%d" % (kargs["host"], kargs["port"]))
        for v in args:
            try:
                res = getattr(s, "get_%s" % v)()
                rv[v] = res
            except xmlrpc.Fault:
                print("Unknown variable '%s'" % v)
        s = None
    if len(args) == 1:
        return rv[args[0]]
    return rv

@conf.commands.register
def gnuradio_stop_graph(host="localhost", port=8080):
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpc is missing to use this function.")
    else:
        s = xmlrpc.Server("http://%s:%d" % (host, port))
        s.stop()
        s.wait()

@conf.commands.register
def gnuradio_start_graph(host="localhost", port=8080):
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpclib is missing to use this function.")
    else:
        s = xmlrpc.Server("http://%s:%d" % (host, port))
        try:
            s.start()
        except xmlrpc.Fault as e:
            print("ERROR: %s" % e.faultString)

@conf.commands.register
def switch_radio_protocol(layer, hardware=None, mode=None, env=None, ch=None, *args, **kargs):
    """Launches Gnuradio in background"""
    if not conf.gr_modulations:
        build_modulations_dict(env=env)
    if not hasattr(conf, 'gr_process_io') or conf.gr_process_io is None:
        conf.gr_process_io = {'stdout': open('/tmp/gnuradio.log', 'w+'), 'stderr': open('/tmp/gnuradio-err.log', 'w+')}
    if layer not in conf.gr_modulations[hardware]:
        print("\nAvailable layers: %s" % ", ".join(conf.gr_modulations.keys()), '\n')
        raise AttributeError("Unknown radio layer %s" % layer)
    if conf.gr_process is not None:
        # An instance is already running
        conf.gr_process.kill()
        conf.gr_process = None
    try:
        conf.gr_process = subprocess.Popen(["python2", conf.gr_modulations[hardware][layer][mode], "-c", str(ch)], env=env, bufsize=0, 
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print('Waiting for {}...'.format(hardware))
        wait_for_hardware(hardware)
        print('Starting Process')
    except OSError:
        return False
    return True

def gnuradio_exit(c):
    if hasattr(c, "gr_process") and hasattr(c.gr_process, "kill"):
        c.gr_process.kill()
    if hasattr(c, "gr_process_io") and c.gr_process_io is dict:
        for k in c.gr_process_io.keys():
            if os.path.isfile(c.gr_process_io[k]) and not c.gr_process_io[k].closed:
                c.gr_process_io[k].close()
                c.gr_process_io[k] = None

atexit.register(gnuradio_exit, conf)
conf.L2socket = GnuradioSocket
conf.L3socket = GnuradioSocket
conf.L2listen = GnuradioSocket
for l in ["ZWave", "gnuradio", "dot15d4", "bluetooth4LE", "wmbus"]:
    main.load_layer(l)
conf.gr_modulations = {}
conf.gr_modulation_options = {}
conf.gr_process = None
conf.gr_mods_path = os.path.join(os.getcwd(), "util", ".scapy")
if not os.path.exists(conf.gr_mods_path):
    os.makedirs(conf.gr_mods_path)
