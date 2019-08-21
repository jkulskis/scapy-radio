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
import datetime
import errno


def find_all_hardware(env=None):
    hardware_checks = [
        ('usrp', 'uhd_find_devices'),
        ('hackrf', 'hackrf_info')
    ]
    available_hardware = []
    for hardware_info in hardware_checks:
        try:  # try to find a usrp first, since full duplex is optimal for testing
            find_process = subprocess.check_call(
                hardware_info[1], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, env=None)
            if find_process == 0:
                available_hardware.append(hardware_info[0])
        except (FileNotFoundError, subprocess.CalledProcessError):
            # if they don't have this hardware's drivers (FileNotFoundError) or one is not plugged in (returns exit code 1), just move on and try for the next hardware
            pass
    return available_hardware


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
        # check if a valid gnuradio protocol, otherwise return a raw Packet
        if p.fields['proto'] not in range(1, 6):
            return Packet(data)
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
        if v is not None:
            if len(arg) == 1:  # using short ID
                paramter_args.append("-" + arg.replace("_", "-"))
            else:  # if len(arg) > 1, then using the full ID
                paramter_args.append("--" + arg.replace("_", "-"))
            paramter_args.append(str(v))
    return paramter_args


def get_parameter(short_id=None, long_id=None, params=[]):
    if short_id and "-" + short_id in params:
        return params[params.index("-" + short_id) + 1]
    elif long_id and "--" + long_id in params:
        return params[params.index("--" + long_id) + 1]
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


def has_scan(protocol):
    protocol = protocol.lower()
    if protocol in conf.gr_modulations.keys():
        for hardware, modes in conf.gr_modulations[protocol].items():
            for mode in modes.keys():
                if mode.startswith('rx'):
                    return True
    return False


def has_transmit(protocol):
    protocol = protocol.lower()
    if protocol in conf.gr_modulations.keys():
        for hardware, modes in conf.gr_modulations[protocol].items():
            for mode in modes.keys():
                if mode.startswith('tx'):
                    return True
    return False


def available_actions(protocol):
    actions = []
    if has_scan(protocol):
        actions.append('scan')
    if has_transmit(protocol):
        actions.append('transmit')
    return actions


@conf.commands.register
def srradio(pkts, inter=0.1, *args, **kargs):
    """send and receive using a Gnuradio socket"""
    s = GnuradioSocket()
    a, b = sendrecv.sndrcv(s, pkts, inter=inter, *args, **kargs)
    s.close()
    return a, b


@conf.commands.register
def sniffradio(opened_socket=None, radio=None, *args, **kargs):
    if radio is not None:
        switch_radio_protocol(radio)
    s = opened_socket if opened_socket is not None else GnuradioSocket()
    rv = sendrecv.sniff(opened_socket=s, *args, **kargs)
    if opened_socket is None:
        s.close()
    return rv


def disable_print():
    sys.stdout = open(os.devnull, 'w')


def enable_print():
    sys.stdout = sys.__stdout__


@conf.commands.register
def kill_process():
    if conf.gr_process is not None and not conf.gr_process.poll():  # check if the process is running
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
    conf.gr_process = None


def build_protocol_mode(protocol=None, mode_path=None, hardware=None, env=None):
    # mode example: tx if the base dir name of the mode_path is Zigbee_tx
    # if no underscore in the base_dir, then set the mode to the whole base_dir name
    if os.path.basename(mode_path):
        base_dir_name = os.path.basename(mode_path)
    else:
        base_dir_name = os.path.basename(os.path.dirname(mode_path))
    mode = base_dir_name[base_dir_name.index(
        "_") + 1:] if "_" in base_dir_name else base_dir_name
    mode = mode.lower()  # for consistency
    file_names = os.listdir(mode_path)
    compiled_file_name = None
    grc_file_name = None
    for file_name in file_names:
        if file_name.endswith('.py'):
            # assume that if there is a python file, it is the compiled block file
            # if there is a top_block file, take that every time
            compiled_file_name = file_name if compiled_file_name != 'top_block.py' else compiled_file_name
        elif file_name.endswith('.grc'):
            # assume that there is only one grc file in the mode_path dir
            grc_file_name = file_name
    if grc_file_name is None and compiled_file_name is None:  # invalid path if no .py file or .grc file
        print(
            f"'{mode_path}' is an invalid protocol mode_path...no .grc or .py file found")
        return 1
    elif compiled_file_name is None:  # check if the grc has been compiled
        try:
            print(f"Compiling {base_dir_name} for {hardware}")
            # try to compile the grc file
            outdir = "--directory=" + mode_path
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
                    compiled_file_name = file_name if compiled_file_name != 'top_block.py' else compiled_file_name
                    break
            assert compiled_file_name is not None
            conf.gr_modulations[hardware][protocol][mode] = os.path.join(
                mode_path, compiled_file_name
            )
        except:  # if compiling the grc failed, then set this protocol mode to None
            print(f"Compilation of {base_dir_name} for {hardware} failed")
            conf.gr_modulations[protocol][hardware][mode] = None
    else:
        conf.gr_modulations[protocol][hardware][mode] = os.path.join(
            mode_path, compiled_file_name)


def update_protocol_mode(protocol=None, mode_path=None, hardware=None, env=None):
    protocol = protocol.lower()
    hardware = hardware.lower()
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


def update_custom_modulation(protocol, hardware, mode, mode_path):
    protocol = protocol.lower()
    hardware = hardware.lower()
    mode = mode.lower()
    if not protocol in conf.gr_modulations:
        conf.gr_modulations[protocol] = {hardware: {mode: mode_path}}
    elif hardware not in conf.gr_modulations[protocol]:
        conf.gr_modulations[protocol][hardware] = {mode: mode_path}
    else:
        conf.gr_modulations[protocol][hardware][mode] = mode_path


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
def gnuradio_set_vars(gr_host="localhost", gr_port=8080, **kwargs):
    if not kwargs:
        return
    try:
        from xmlrpc.client import Server
        from xmlrpc.client import Fault
    except ImportError:
        print("xmlrpc is needed to call 'gnuradio_set_vars'")
    else:
        s = Server(f"http://{gr_host}:{gr_port}")
        for k, v in kwargs.items():
            try:
                getattr(s, f"set_{k}")(v)
            except Fault:
                print(f"Unknown variable '{k}'")
        s = None


@conf.commands.register
def wait_for_radio(gr_host="localhost", gr_port=8080, timeout=20):
    try:
        from xmlrpc.client import Server
        from xmlrpc.client import Fault
    except ImportError:
        print("xmlrpc is needed to use 'wait_for_radio'")
        print("Waiting for 10s statically instead...")
        time.sleep(10)
    print("Waiting 20s for the SDR to start up", end='')
    start_time = time.time()
    while 1:
        try:
            disable_print()
            # try to connect to the XMLRPC server in the flowgraph
            gnuradio_get_vars('startup_var')
            enable_print()
            print("")
            break
        except socket.error as e:
            enable_print()
            if e.errno is errno.ECONNREFUSED:
                if time.time() - start_time > timeout:
                    print(f"Could not connect to the SDR within {timeout} seconds. Exiting...")
                    sys.exit(1)
                print('.', end='')
                sys.stdout.flush()
                time.sleep(.5)
                continue
            elif e.errno is errno.ECONNRESET:
                print("\nSDR not connected. Exiting...")
                sys.exit(1)
            else:
                enable_print()
                raise(e)
        except KeyError: # may not have a varaible called "startup_var" in the flowgraph, but that's fine 
            pass
        enable_print()
        time.sleep(0.5) # wait an extra 0.5 seconds so that everything is up and running
        print("")
        break


@conf.commands.register
def gnuradio_get_vars(*args, **kwargs):
    if "gr_host" not in kwargs:
        kwargs["gr_host"] = "127.0.0.1"
    if "gr_port" not in kwargs:
        kwargs["gr_port"] = 8080
    rv = {}
    try:
        from xmlrpc.client import Server
        from xmlrpc.client import Fault
    except ImportError:
        print("xmlrpc is needed to call 'gnuradio_get_vars'")
    else:
        s = Server(f"http://{kwargs['gr_host']}:{kwargs['gr_port']}")
        for v in args:
            try:
                res = getattr(s, f"get_{v}")()
                rv[v] = res
            except Fault:
                print(f"Unknown variable '{v}'")
        s = None
    if len(args) == 1:
        return rv[args[0]]
    return rv


@conf.commands.register
def gnuradio_stop_graph(gr_host="localhost", gr_port=8080):
    try:
        from xmlrpc.client import Server
        from xmlrpc.client import Fault
    except ImportError:
        print("xmlrpc is needed to call 'gnuradio_stop_graph'")
    else:
        s = Server(f"http://{gr_host}:{gr_port}")
        s.stop()
        s.wait()


@conf.commands.register
def gnuradio_start_graph(gr_host="localhost", gr_port=8080):
    try:
        from xmlrpc.client import Server
        from xmlrpc.client import Fault
    except ImportError:
        print("xmlrpclib is needed to call 'gnuradio_start_graph'")
    else:
        s = Server(f"http://{gr_host}:{gr_port}")
        try:
            s.start()
        except Fault as e:
            print(f"ERROR: {e.faultString}")


@conf.commands.register
def switch_radio_protocol(
    protocol,
    modes=None,
    params=[],
    env=None,
    hardware=None,
    *args,
    **kwargs,
):
    if conf.gr_process is not None:
        return True  # don't switch if something is already running
    protocol = protocol.lower()
    if isinstance(modes, str):
        modes = [modes.lower()]
    elif isinstance(modes, list):
        modes = [mode.lower() for mode in modes]
    else:
        raise AttributeError("Invalid Mode / Mode List")
    """Launches Gnuradio in background"""
    if not conf.gr_modulations:
        build_modulations_dict(env=env)
    conf.gr_process_io = {
        "stdout": open("/tmp/gnuradio.log", "w+"),
        "stderr": open("/tmp/gnuradio-err.log", "w+"),
    }
    if protocol not in conf.gr_modulations:
        # check to see if the casing was off
        lower_keys = [key.lower() for key in conf.gr_modulations.keys()]
        try:
            protocol = list(conf.gr_modulations.keys())[
                lower_keys.index(protocol.lower())]
        except ValueError:
            available_protocols = []
            for protocol, hardwares in conf.gr_modulations.items():
                if hardware in hardwares.keys():
                    available_protocols.append(protocol)
            print(
                "Invalid protocol\nAvailable protocols for {}: {}\n".format(
                    hardware, ", ".join(available_protocols)
                )
            )
            raise AttributeError(f"Unknown radio protocol: {protocol}")
    if conf.gr_process is not None:
        # An instance is already running
        kill_process()
        conf.gr_process = None
    for mode in modes:
        try:
            if conf.gr_modulations[protocol][hardware][mode].endswith('.py'):
                full_cmd = ["python2", conf.gr_modulations[protocol]
                            [hardware][mode]] + params
            elif conf.gr_modulations[protocol][hardware][mode].endswith('.sh'):
                full_cmd = ["./" + conf.gr_modulations[protocol]
                            [hardware][mode]] + params
            else:
                full_cmd = [conf.gr_modulations[protocol]
                            [hardware][mode]] + params
            conf.gr_process = subprocess.Popen(
                full_cmd,
                env=env,
                bufsize=1,
                stdout=conf.gr_process_io["stdout"],
                stderr=conf.gr_process_io["stderr"],
                stdin=subprocess.PIPE,
            )
            wait_for_radio()
            return True
        except OSError:
            return False
        except KeyError:  # mode doesn't exist for this hardware
            pass
    return False


def output():
    if not hasattr(conf, "gr_process_io") or conf.gr_process_io is None:
        return None
    else:
        return conf.gr_process_io


def gnuradio_exit(c):
    if hasattr(c, "gr_process") and hasattr(c.gr_process, "kill"):
        c.gr_process.kill()
    if hasattr(c, "gr_process_io") and c.gr_process_io is dict:
        for k in c.gr_process_io.keys():
            if os.path.isfile(c.gr_process_io[k]) and not c.gr_process_io[k].closed:
                c.gr_process_io[k].close()
                c.gr_process_io[k] = None


def initial_setup():
    from pathlib import Path
    conf.gr_mods_path = os.path.join(str(Path.home()), '.scapy-radio')
    if not os.path.exists(conf.gr_mods_path):
        os.makedirs(conf.gr_mods_path)
    atexit.register(gnuradio_exit, conf)
    conf.L2socket = GnuradioSocket
    conf.L3socket = GnuradioSocket
    conf.L2listen = GnuradioSocket
    for l in ["ZWave", "gnuradio", "dot15d4", "bluetooth4LE", "wmbus"]:
        main.load_layer(l)
    conf.gr_modulations = {}
    conf.gr_protocol_options = {}
    conf.gr_process = None
    build_modulations_dict()


initial_setup()
