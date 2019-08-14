# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) John Mikulskis <jkulskis@bu.edu>
# This program is published under a GPLv2 license

"""
RFTap (RFtap RF Protocol).
"""

from scapy.layers.dot11 import Dot11
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.utils import lhex
    
class LE_IEEEFloatField(IEEEFloatField):
    def __init__(self, name, default, fmt="<f"):
        Field.__init__(self, name, default, fmt)


class LE_IEEEDoubleField(IEEEDoubleField):
    def __init__(self, name, default, fmt="<d"):
        Field.__init__(self, name, default, fmt)

class LE_XBitField(XBitField):
    def __init__(self, name, default, size, fmt="<"):
        Field.__init__(self, name, default, fmt)
        self.rev = size < 0
        self.size = abs(size)

class RFtap(Packet):
    name = "RFtap Protocol"
    fields_desc = [
        LE_XBitField("magic", "RFta", 32),
        LE_XBitField("length32", 0, 16),
        FlagsField("flags", 0, 16, ["qual", "isunixtime", "time", "duration", "location",
                                    "reserved1", "reserved2", "reserved3", "dlt", "freq", 
                                    "nomfreq", "freqofs", "isdbm", "power",
                                    "noise", "snr"]),
        ConditionalField(
            LEIntField("dlt", 0),
            lambda pkt: (pkt.flags and pkt.flags.dlt),
        ),
        ConditionalField(
            LE_IEEEDoubleField("freq", 0),
            lambda pkt: (pkt.flags and pkt.flags.freq),
        ),
        ConditionalField(
            LE_IEEEDoubleField("nomfreq", 0),
            lambda pkt: (pkt.flags and pkt.flags.nomfreq),
        ),
        ConditionalField(
            LE_IEEEDoubleField("freqofs", 0),
            lambda pkt: (pkt.flags and pkt.flags.freqofs),
        ),
        ConditionalField(
            BitEnumField("isdbm", 0, 1, {0: 'power units are dB', 1: 'the power units are dBm'}),
            lambda pkt: (pkt.flags and pkt.flags.isdbm),
        ),
        ConditionalField(
            LE_IEEEFloatField("power", 0),
            lambda pkt: (pkt.flags and pkt.flags.power),
        ),
        ConditionalField(
            LE_IEEEFloatField("noise", 0),
            lambda pkt: (pkt.flags and pkt.flags.noise),
        ),
        ConditionalField(
            LE_IEEEFloatField("snr", 0),
            lambda pkt: (pkt.flags and pkt.flags.snr),
        ),
        ConditionalField(
            LE_IEEEFloatField("qual", 0),
            lambda pkt: (pkt.flags and pkt.flags.qual),
        ),
        ConditionalField(
            BitEnumField("isunixtime", 0, 1, {0: 'the time standard is not defined', 1: 'the time standard is unix time'}),
            lambda pkt: (pkt.flags and pkt.flags.isunixtime),
        ),
        ConditionalField(
            LE_IEEEDoubleField("timeint", 0),
            lambda pkt: (pkt.flags and pkt.flags.time),
        ),
        ConditionalField(
            LE_IEEEDoubleField("timefrac", 0),
            lambda pkt: (pkt.flags and pkt.flags.time),
        ),
        ConditionalField(
            LE_IEEEDoubleField("duration", 0),
            lambda pkt: (pkt.flags and pkt.flags.duration),
        ),
        ConditionalField(
            LE_IEEEDoubleField("lat", 0),
            lambda pkt: (pkt.flags and pkt.flags.location),
        ),
        ConditionalField(
            LE_IEEEDoubleField("lon", 0),
            lambda pkt: (pkt.flags and pkt.flags.location),
        ),
        ConditionalField(
            LE_IEEEDoubleField("alt", 0),
            lambda pkt: (pkt.flags and pkt.flags.location),
        ),
    ]

bind_layers(RFtap, Dot11, dlt=105)
bind_layers(RFtap, Dot15d4FCS, dlt=195)
bind_layers(RFtap, Dot15d4, dlt=230)
