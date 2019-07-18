# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Airbus DS CyberSecurity
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
# This program is published under a GPLv2 license

"""
Gnuradio layers, sockets and send/receive functions.
"""

import socket
import struct
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
        self.outs = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
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

    def send(self, pkt):
        if not pkt.haslayer(scapy.layers.gnuradio.GnuradioPacket):
            pkt = scapy.layers.gnuradio.GnuradioPacket() / pkt
        if isinstance(pkt, bytes):
            sx = pkt
        else:
            sx = bytes(pkt)
        self.outs.sendto(sx, self.tx_addr)


def parse_parameters(**kwargs):
    paramter_args = []
    for arg, v in kwargs.items():
        if len(arg) == 1:  # using short ID
            paramter_args.append('-{}'.format(arg))
        else:  # if len(arg) > 1, then using the full ID
            paramter_args.append('--{}'.format(arg))
        paramter_args.append(str(v))
    return paramter_args


def get_parameter(short_id=None, long_id=None, params=[]):
    if short_id and '-{}'.format(short_id) in params:
        return params[params.index('-{}'.format(short_id)) + 1]
    elif long_id and '--{}'.format(long_id) in params:
        return params[params.index('--{}'.format(long_id)) + 1]
    else:
        return None


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
        # need to change to usrp specific string since press enter to quit takes time to load up
        load_string = 'Press Enter to quit'
        busy_string = 'Resource busy'
    elif hardware == 'hackrf':
        load_string = 'Using HackRF'
        busy_string = 'Resource busy'
    while True:
        # don't read constantly to avoid creating a heavy process
        time.sleep(.1)
        conf.gr_process_io['stderr'].seek(0)
        out = conf.gr_process_io['stderr'].read()
        if out:
            if load_string in out:
                # wait an extra half second, since there is a small delay
                time.sleep(0.5)
                return 0
            elif busy_string in out:
                return 1


@conf.commands.register
def srradio(pkts, radio=None, hardware=None, listen=True, wait_every=True, wait_timeout=0.25, env=None, preamble_fuzz=False,
            params=[], prn=None, *args, **kwargs):
    """send and receive using a Gnuradio socket"""
    ch = get_parameter(short_id='c', long_id='channel', params=params)
    print('Sending on channel {}'.format(ch))
    rx_packets = []
    if radio is not None:
        if hardware == 'usrp':
            if preamble_fuzz:
                pass
                if not switch_radio_protocol(
                        radio, hardware=hardware, env=env, mode='rf_fuzz', params=params):
                    return []
            else:
                if not switch_radio_protocol(
                        radio, hardware=hardware, env=env, mode='rf', params=params):
                    return []
        elif hardware == 'hackrf':
            if not switch_radio_protocol(radio, hardware=hardware,
                                     env=env, mode='tx', params=params):
                return []
    s = GnuradioSocket()
    number = 0
    for pkt in pkts:
        number += 1
        s.send(pkt)
        if prn:
            prn(pkt, number, tx=True)
        if wait_every:
            if hardware == 'ursp':
                print('Waiting {} seconds for responses...'.format(wait_timeout))
                rv = sendrecv.sniff(opened_socket=s, timeout=wait_timeout)
                for r_pkt in rv:
                    if r_pkt is not None and str(r_pkt) != str(pkt):
                        if prn:
                            prn(pkt, number)
                        rx_packets.append(r_pkt)
            elif hardware == 'hackrf':
                # hackrf can't listen in between, but may want to simply wait in between
                time.sleep(wait_timeout)
    # can't receive + transmit with the hackrf...could start up a new tx flowgraph but that takes too much time
    if not wait_every and hardware != 'hackrf':
        pkt_strings = [str(pkt) for pkt in pkts]
        print('Waiting {} seconds for responses...'.format(wait_timeout))
        rv = sendrecv.sniff(opened_socket=s, timeout=wait_timeout)
        for r_pkt in rv:
            if r_pkt != None:
                if str(r_pkt) not in pkt_strings:  # make sure that it isn't a duplicate
                    if prn:
                        prn(pkt, number)
                    rx_packets.append(r_pkt)
    print('Closing socket...')
    # sleep for a couple seconds in case the socket was blocked up
    time.sleep(2)
    s.close()
    kill_process()
    return rx_packets


@conf.commands.register
def srradio1(pkts, radio=None, hardware=None, env=None, params=[], *args, **kwargs):
    """send and receive 1 packet using a Gnuradio socket"""
    a, b = srradio(pkts, radio=radio, env=env, params=params, *args, **kwargs)
    if len(a) > 0:
        return a[0][1]


@conf.commands.register
def sniffradio(radio=None, hardware=None, env=None, opened_socket=None, params=[], *args, **kwargs):
    if radio is not None:
        if not switch_radio_protocol(radio, hardware=hardware,
                              env=env, mode='rx', params=params):
            return []
    s = opened_socket if opened_socket is not None else GnuradioSocket()
    ch = get_parameter(short_id='c', long_id='channel', params=params)
    print('Sniffing on channel {}'.format(ch))
    rv = sendrecv.sniff(opened_socket=s, *args, **kwargs)
    if opened_socket is None:
        s.close()
    kill_process()
    return rv


@conf.commands.register
def kill_process():
    if not conf.gr_process.poll():  # check if the process is running
        # send a newline to gracefully stop the gnruadio process before killing
        conf.gr_process.stdin.write('\r\n'.encode())
        conf.gr_process.stdin.close()
        conf.gr_process.kill()


def build_modulations_dict(env=None):
    hardwares = ['hackrf', 'usrp']
    for hardware in hardwares:
        hardware_dir = os.path.join(conf.gr_mods_path, hardware)
        conf.gr_modulations[hardware] = dict.fromkeys(
            [x for x in os.listdir(hardware_dir)])  # Find what modulation folders exist
        for modulation in conf.gr_modulations[hardware]:
            # set as empty dict one at a time to avoid references to the same dict
            conf.gr_modulations[hardware][modulation] = {}
            for mode in os.listdir(os.path.join(hardware_dir, modulation)):
                if '_' in mode:
                    # keyword example: tx, rx
                    keyword = mode[mode.index('_') + 1:]
                    keyword_files = os.listdir(
                        os.path.join(hardware_dir, modulation, mode))
                    if 'top_block.py' not in keyword_files:  # check if the grc has been compiled
                        try:
                            print('Compiling {0} for {1}'.format(
                                mode, hardware))
                            # try to compile the grc file
                            outdir = "--directory=%s" % os.path.join(
                                hardware_dir, modulation, mode)
                            subprocess.check_call(['grcc', outdir, os.path.join(
                                hardware_dir, modulation, mode, keyword_files[0])], env=env)
                            conf.gr_modulations[hardware][modulation][keyword] = os.path.join(
                                hardware_dir, modulation, mode, 'top_block.py')
                        except:  # if compiling the grc failed, then set this modulation keyword to None
                            conf.gr_modulations[hardware][modulation][keyword] = None
                    else:
                        conf.gr_modulations[hardware][modulation][keyword] = os.path.join(
                            hardware_dir, modulation, mode, 'top_block.py')


def strip_gnuradio_layer(packets):
    if isinstance(packets, list):
        new_packets = []
        for ii in range(len(packets)):
            if packets[ii].haslayer(scapy.layers.gnuradio.GnuradioPacket):
                new_packets.append(packets[ii].payload)
            else:
                new_packets.append(packets[ii])
        return new_packets
    else:
        if packets.haslayer(scapy.layers.gnuradio.GnuradioPacket):
            return packets.payload
        else:
            return packets


def sigint_ignore():
    import os
    os.setpgrp()


@conf.commands.register
def gnuradio_set_vars(host="localhost", port=8080, **kwargs):
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpc is missing to use this function.")
    else:
        s = xmlrpc.Server("http://%s:%d" % (host, port))
        for k, v in kwargs.iteritems():
            try:
                getattr(s, "set_%s" % k)(v)
            except xmlrpc.Fault:
                print("Unknown variable '%s'" % k)
        s = None


@conf.commands.register
def gnuradio_get_vars(*args, **kwargs):
    if "host" not in kwargs:
        kwargs["host"] = "127.0.0.1"
    if "port" not in kwargs:
        kwargs["port"] = 8080
    rv = {}
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpc is missing to use this function.")
    else:
        s = xmlrpc.Server("http://%s:%d" % (kwargs["host"], kwargs["port"]))
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
        s = xmlrpc.Server("http://{host}:{port}".format(host=host, port=port))
        s.stop()
        s.wait()


@conf.commands.register
def gnuradio_start_graph(host="localhost", port=8080):
    try:
        import xmlrpc
    except ImportError:
        print("xmlrpclib is missing to use this function.")
    else:
        s = xmlrpc.Server("http://{host}:{port}".format(host=host, port=port))
        try:
            s.start()
        except xmlrpc.Fault as e:
            print("ERROR: {}".format(e.faultString))


@conf.commands.register
def switch_radio_protocol(layer, hardware=None, mode=None, env=None, params=[], *args, **kwargs):
    """Launches Gnuradio in background"""
    if not conf.gr_modulations:
        build_modulations_dict(env=env)
    if not hasattr(conf, 'gr_process_io') or conf.gr_process_io is None:
        conf.gr_process_io = {'stdout': open(
            '/tmp/gnuradio.log', 'w+'), 'stderr': open('/tmp/gnuradio-err.log', 'w+')}
    if layer not in conf.gr_modulations[hardware]:
        print("\nAvailable layers: %s" % ", ".join(
            conf.gr_modulations[hardware].keys()), '\n')
        raise AttributeError("Unknown radio layer %s" % layer)
    if conf.gr_process is not None:
        # An instance is already running
        kill_process()
        conf.gr_process = None
    try:
        # conf.gr_process = subprocess.Popen(["python2", conf.gr_modulations[hardware][layer][mode]] + params, env=env, bufsize=1,
        #                                    stdout=conf.gr_process_io['stdout'], stderr=conf.gr_process_io['stderr'], stdin=subprocess.PIPE)
        conf.gr_process = subprocess.Popen(["python2", conf.gr_modulations[hardware][layer][mode]] + params, env=env, bufsize=1,
                                           stderr=conf.gr_process_io['stderr'], stdin=subprocess.PIPE)
        print('Waiting for {}...'.format(hardware))
        if wait_for_hardware(hardware) == 1:
            print('{} is Busy'.format(hardware))
            return False
        else:
            print('Loaded up {}'.format(hardware))
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
