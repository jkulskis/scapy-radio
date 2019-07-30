# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Airbus DS CyberSecurity
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
# This program is published under a GPLv2 license

"""
Gnuradio layers, sockets and send/receive functions.
"""

from scapy.config import conf
from scapy.data import MTU
from scapy.packet import *
from scapy.fields import *
from scapy.supersocket import SuperSocket
from scapy import sendrecv
from scapy import main
from appdirs import user_data_dir
import socket
import struct
import atexit
import scapy.layers.gnuradio
import os
import sys
import subprocess
import time


class Radio:
    def __init__(self, hardware=None, env=None):
        # usrp, hackrf, etc.
        self.env = env
        self.hardware = self.detect_hardware(hardware)
        self.protocols = {}
        self.update_protocols()

    def update_protocols(self):
        try:
            for protocol, hardwares in conf.gr_modulations.items():
                if self.hardware in hardwares.keys():
                    self.protocols[protocol] = conf.gr_modulations[protocol][self.hardware]
        except AttributeError:  # conf.gr_modulations hasn't been loaded up yet
            initial_setup()
            self.update_protocols()

    def protocol_modes(self, protocol):
        self.update_protocols()
        return list(self.protocols[protocol].keys())

    def detect_hardware(self, hardware=None):
        hardware_checks = [('usrp', 'uhd_find_devices'),
                           ('hackrf', 'hackrf_info')]
        if hardware:  # if using a specific hardware, only try to detect the given hardware type
            supported = False
            for hardware_info in hardware_checks:
                if hardware_info[0] == hardware:
                    hardware_checks = [hardware_info]
                    supported = True
                    break
            if not supported:
                print("Could not find supported hardware\n")
                return None
        print("Trying to find supported hardware: {}".format(
            ', '.join(hardware_info[0] for hardware_info in hardware_checks)))
        for hardware_info in hardware_checks:
            try:  # try to find a usrp first, since full duplex is optimal for testing
                find_process = subprocess.check_call(
                    hardware_info[1], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, env=self.env)
                if find_process == 0:
                    print("Using hardware: {}".format(hardware_info[0]))
                    return hardware_info[0]
            except (FileNotFoundError, subprocess.CalledProcessError):
                # if they don't have this hardware's drivers (FileNotFoundError) or one is not plugged in (returns exit code 1), just move on and try for the next hardware
                pass
        print("Could not find supported hardware")
        return None

    def wait_for_hardware(self):
        if self.hardware == "usrp":
            # need to change to usrp specific string since press enter to quit takes time to load up
            load_string = "Actually got clock rate 32.000000 MHz"
            busy_string = "KeyError: No devices found for"
            sleep_time = 1.5
        elif self.hardware == "hackrf":
            load_string = "Using HackRF"
            busy_string = "Resource busy"
            sleep_time = 0.5
        else:
            time.sleep(10)  # unrecognized hardware...sleep for 10s to load up
            return 0
        print("\nWaiting for {}...".format(self.hardware))
        while True:
            # don't read constantly to avoid creating a heavy process
            time.sleep(0.2)
            conf.gr_process_io["stderr"].seek(0)
            out = conf.gr_process_io["stderr"].read()
            if out:
                if load_string in out:
                    # wait the extra sleep time, since there is a small delay
                    time.sleep(sleep_time)
                    print("Loaded up {}".format(self.hardware))
                    return True
                elif busy_string in out:
                    print("{} is Busy".format(self.hardware))
                    return False
            if conf.gr_process.poll():  # check if the process exited before the hardware loaded up
                print("Error: Process exited before {} loaded up\n".format(
                    self.hardware))
                print("Gnuradio-err log:\n\n{0}".format(out))
                return False


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
        pkt.time = time.time()
        self.outs.sendto(sx, self.tx_addr)


def parse_parameters(**kwargs):
    paramter_args = []
    for arg, v in kwargs.items():
        if len(arg) == 1:  # using short ID
            paramter_args.append("-{}".format(arg.replace("_", "-")))
        else:  # if len(arg) > 1, then using the full ID
            paramter_args.append("--{}".format(arg.replace("_", "-")))
        paramter_args.append(str(v))
    return paramter_args


def get_parameter(short_id=None, long_id=None, params=[]):
    if short_id and "-{}".format(short_id) in params:
        return params[params.index("-{}".format(short_id)) + 1]
    elif long_id and "--{}".format(long_id) in params:
        return params[params.index("--{}".format(long_id)) + 1]
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
    if hardware == "usrp":
        # need to change to usrp specific string since press enter to quit takes time to load up
        load_string = "Actually got clock rate 32.000000 MHz"
        busy_string = "KeyError: No devices found for"
        sleep_time = 1.5
    elif hardware == "hackrf":
        load_string = "Using HackRF"
        busy_string = "Resource busy"
        sleep_time = 0.5
    while True:
        # don't read constantly to avoid creating a heavy process
        time.sleep(0.1)
        conf.gr_process_io["stderr"].seek(0)
        out = conf.gr_process_io["stderr"].read()
        if out:
            if load_string in out:
                # wait an extra half second, since there is a small delay
                time.sleep(sleep_time)
                return 0
            elif busy_string in out:
                return 1


@conf.commands.register
def srradio(
    pkts,
    protocol=None,
    radio=None,
    listen=True,
    wait_times=0.25,
    env=None,
    preamble_fuzz=False,
    params=[],
    prn=None,
    *args,
    **kwargs
):
    """send and receive using a Gnuradio socket"""
    ch = get_parameter(short_id="c", long_id="channel", params=params)
    print("\nSending on channel {}".format(ch))
    rx_packets = []
    if radio.hardware == "usrp":
        if preamble_fuzz:
            if not switch_radio_protocol(
                protocol, radio=radio, env=env, mode="rf_fuzz", params=params
            ):
                return []
        else:
            if not switch_radio_protocol(
                protocol, radio=radio, env=env, mode="rf", params=params
            ):
                return []
    elif radio.hardware == "hackrf":
        if preamble_fuzz:
            if not switch_radio_protocol(
                protocol, radio=radio, env=env, mode="tx_fuzz", params=params
            ):
                return []
        else:
            if not switch_radio_protocol(
                protocol, radio=radio, env=env, mode="tx", params=params
            ):
                return []
    else:  # if not a known radio, try to use rf / tx
        if not switch_radio_protocol(
                protocol, radio=radio, env=env, mode="rf", params=params
        ):
            if not switch_radio_protocol(
                protocol, radio=radio, env=env, mode="tx", params=params
            ):
                return []
    s = GnuradioSocket()
    number = 0
    pkt_strings = [str(pkt) for pkt in strip_gnuradio_layer(pkts)]
    if not isinstance(wait_times, list):  # either list, numeral, or None
        wait_times = [wait_times] * len(pkts)
    for ii in range(len(pkts)):
        number += 1
        s.send(pkts[ii])
        if prn:
            prn(pkts[ii], number, tx=True)
        if wait_times[ii]:
            print("Waiting {} seconds...".format(wait_times[ii]))
            if radio.hardware == "usrp":
                rv = sendrecv.sniff(opened_socket=s, timeout=wait_times[ii])
                for r_pkt in rv:
                    if (
                        r_pkt is not None
                        and str(strip_gnuradio_layer(r_pkt)) != pkt_strings[ii]
                    ):
                        if prn:
                            prn(r_pkt)
                        rx_packets.append(r_pkt)
            elif radio.hardware == "hackrf":
                time.sleep(wait_times[ii])
    # can't receive + transmit with the hackrf...could start up a new tx flowgraph but that takes too much time
    if radio.hardware != "hackrf":
        print("Emptying socket of any responses...")
        rv = sendrecv.sniff(
            opened_socket=s, timeout=3
        )  # wait 3 seconds to empty the socket
        for r_pkt in rv:
            if (
                r_pkt is not None
                and str(strip_gnuradio_layer(r_pkt)) not in pkt_strings
            ):
                rx_packets.append(r_pkt)
    else:
        print("Closing socket...")
    s.close()
    kill_process()
    return rx_packets


@conf.commands.register
def srradio1(pkts, protocol=None, radio=None, env=None, params=[], *args, **kwargs):
    """send and receive 1 packet using a Gnuradio socket"""
    a, b = srradio(pkts, protocol=protocol, radio=radio,
                   env=env, params=params, *args, **kwargs)
    if len(a) > 0:
        return a[0][1]


@conf.commands.register
def sniffradio(
    protocol=None, radio=None, env=None, opened_socket=None, params=[], *args, **kwargs
):
    if protocol is not None:
        if not switch_radio_protocol(
            protocol, radio=radio, env=env, mode="rx", params=params
        ):
            return []
    s = opened_socket if opened_socket is not None else GnuradioSocket()
    ch = get_parameter(short_id="c", long_id="channel", params=params)
    print("\nSniffing on channel {}".format(ch))
    rv = sendrecv.sniff(opened_socket=s, *args, **kwargs)
    if opened_socket is None:
        s.close()
    kill_process()
    return rv


@conf.commands.register
def kill_process():
    if not conf.gr_process.poll():  # check if the process is running
        # send a newline to gracefully stop the gnruadio process before killing
        try:
            conf.gr_process.stdin.write("\r\n".encode())
            conf.gr_process.stdin.close()
        except ValueError:  # may be closed
            pass
        for k, v in conf.gr_process_io.items():
            if not v.closed:
                v.close()
                v = None
        conf.gr_process.kill()


def build_protocol_mode(protocol=None, mode_path=None, hardware=None, env=None):
    # mode example: tx if the base dir name of the mode_path is Zigbee_tx
    # if no underscore in the base_dir, then set the mode to the whole base_dir name
    if os.path.basename(mode_path):
        base_dir_name = os.path.basename(mode_path)
    else:
        base_dir_name = os.path.basename(os.path.dirname(mode_path))
    mode = base_dir_name[base_dir_name.index(
        "_") + 1:] if "_" in base_dir_name else base_dir_name
    file_names = os.listdir(mode_path)
    compiled_file_name = None
    grc_file_name = None
    for file_name in file_names:
        if file_name.endswith('.py'):
            # assume that if there is a python file, it is the compiled block file
            compiled_file_name = file_name
        elif file_name.endswith('.grc'):
            # assume that there is only one grc file in the mode_path dir
            grc_file_name = file_name
    if grc_file_name is None and compiled_file_name is None:  # invalid path if no .py file or .grc file
        print('"{}" is an invalid protocol mode_path...no .grc or .py file found'.format(
            mode_path))
        return 1
    elif compiled_file_name is None:  # check if the grc has been compiled
        try:
            print("Compiling {0} for {1}".format(
                base_dir_name, hardware))
            # try to compile the grc file
            outdir = "--directory={}".format(mode_path)
            grc_file_path = os.path.join(mode_path, grc_file_name)
            subprocess.check_call(
                [
                    "grcc",
                    outdir,
                    grc_file_path,
                ],
                env=env,
            )
            # grab the file names again after compilation
            file_names = os.listdir(mode_path)
            for file_name in file_names:
                if file_name.endswith('.py'):
                    # assume that if there is a python file, it is the compiled block file
                    compiled_file_name = file_name
                    break
            assert compiled_file_name is not None
            conf.gr_modulations[hardware][protocol][mode] = os.path.join(
                mode_path, compiled_file_name
            )
        except:  # if compiling the grc failed, then set this protocol mode to None
            print("Compilation of {0} for {1} failed".format(
                base_dir_name, hardware))
            conf.gr_modulations[protocol][hardware][mode] = None
    else:
        conf.gr_modulations[protocol][hardware][mode] = os.path.join(
            mode_path, compiled_file_name)


def update_protocol_mode(protocol=None, mode_path=None, hardware=None, env=None):
    if protocol not in conf.gr_modulations:
        conf.gr_modulations[protocol] = {hardware: {}}
    elif hardware not in conf.gr_modulations[protocol]:
        conf.gr_modulations[protocol][hardware] = {}
    build_protocol_mode(protocol=protocol, mode_path=mode_path,
                        hardware=hardware, env=env)


def update_hardware(hardware_path=None, protocol=None, env=None):
    if not protocol:
        print('The protocol that this hardware directory is for must be given')
        return 1
    if os.path.basename(hardware_path):
        hardware = os.path.basename(hardware_path)
    else:
        hardware = os.path.basename(os.path.dirname(hardware_path))
    for mode_path in [f.path for f in os.scandir(hardware_path) if f.is_dir()]:
        update_protocol_mode(
            protocol=protocol, mode_path=mode_path, hardware=hardware, env=env)


def update_protocol(protocol_path=None, env=None):
    if os.path.basename(protocol_path):
        protocol = os.path.basename(protocol_path)
    else:
        protocol = os.path.basename(os.path.dirname(protocol_path))
    for hardware_path in [f.path for f in os.scandir(protocol_path) if f.is_dir()]:
        update_hardware(hardware_path=hardware_path,
                        protocol=protocol, env=env)


def build_modulations_dict(env=None):
    for protocol_path in [f.path for f in os.scandir(conf.gr_mods_path) if f.is_dir()]:
        update_protocol(protocol_path=protocol_path, env=env)


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
def switch_radio_protocol(
    protocol, radio=None, mode=None, env=None, params=[], *args, **kwargs
):
    hardware = radio.hardware
    """Launches Gnuradio in background"""
    if not conf.gr_modulations:
        build_modulations_dict(env=env)
    if not hasattr(conf, "gr_process_io") or conf.gr_process_io is None:
        conf.gr_process_io = {
            "stdout": open("/tmp/gnuradio.log", "w+"),
            "stderr": open("/tmp/gnuradio-err.log", "w+"),
        }
    
    if protocol not in conf.gr_modulations:
        available_protocols = []
        for protocol, hardwares in conf.gr_modulations.items():
            if radio.hardware in hardwares.keys():
                available_protocols.append(protocol)
        print(
            "Invalid protocol\nAvailable protocols for {}: {}\n".format(radio.hardware, ", ".join(
                available_protocols))
        )
        raise AttributeError("Unknown radio protocol".format(protocol))
    if conf.gr_process is not None:
        # An instance is already running
        kill_process()
        conf.gr_process = None
    try:
        conf.gr_process = subprocess.Popen(
            ["python2", conf.gr_modulations[protocol][hardware][mode]] + params,
            env=env,
            bufsize=1,
            stdout=conf.gr_process_io["stdout"],
            stderr=conf.gr_process_io["stderr"],
            stdin=subprocess.PIPE,
        )
        return radio.wait_for_hardware()
    except (OSError, KeyError):
        return False


def gnuradio_exit(c):
    if hasattr(c, "gr_process") and hasattr(c.gr_process, "kill"):
        c.gr_process.kill()
    if hasattr(c, "gr_process_io") and c.gr_process_io is dict:
        for k in c.gr_process_io.keys():
            if os.path.isfile(c.gr_process_io[k]) and not c.gr_process_io[k].closed:
                c.gr_process_io[k].close()
                c.gr_process_io[k] = None


def initial_setup():
    atexit.register(gnuradio_exit, conf)
    conf.L2socket = GnuradioSocket
    conf.L3socket = GnuradioSocket
    conf.L2listen = GnuradioSocket
    for l in ["ZWave", "gnuradio", "dot15d4", "bluetooth4LE", "wmbus"]:
        main.load_layer(l)
    conf.gr_modulations = {}
    conf.gr_protocol_options = {}
    conf.gr_process = None
    conf.gr_mods_path = os.path.join(os.getcwd(), "util", ".scapy")
    build_modulations_dict()
    if not os.path.exists(conf.gr_mods_path):
        os.makedirs(conf.gr_mods_path)


initial_setup()
