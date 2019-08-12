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


class RFtap(Packet):
    name = "RFtap Protocol"
    fields_desc = [
        BitField("magic", 0, 32),
        #Field("magic", "RFta", "<4sHH"),
        BitField("length32", 0, 16),
        FlagsField("flags", 0, 16, ["dlt", "freq", "nomfreq", "freqofs", "isdbm", "power",
                                    "noise", "snr", "qual", "isunixtime", "time", "duration", "location",
                                    "reserved1", "reserved2", "reserved3"]),
        ConditionalField(
            LEIntField("dlt", 0),
            lambda pkt: (pkt.flags and pkt.flags.dlt),
        ),
        ConditionalField(
            IEEEDoubleField("freq", 0),
            lambda pkt: (pkt.flags and pkt.flags.freq),
        ),
        ConditionalField(
            IEEEDoubleField("nomfreq", 0),
            lambda pkt: (pkt.flags and pkt.flags.nomfreq),
        ),
        ConditionalField(
            IEEEDoubleField("freqofs", 0),
            lambda pkt: (pkt.flags and pkt.flags.freqofs),
        ),
        ConditionalField(
            BitEnumField("isdbm", 0, 1, {0: 'power units are dB', 1: 'the power units are dBm'}),
            lambda pkt: (pkt.flags and pkt.flags.isdbm),
        ),
        ConditionalField(
            IEEEFloatField("power", 0),
            lambda pkt: (pkt.flags and pkt.flags.power),
        ),
        ConditionalField(
            IEEEFloatField("noise", 0),
            lambda pkt: (pkt.flags and pkt.flags.noise),
        ),
        ConditionalField(
            IEEEFloatField("snr", 0),
            lambda pkt: (pkt.flags and pkt.flags.snr),
        ),
        ConditionalField(
            IEEEFloatField("qual", 0),
            lambda pkt: (pkt.flags and pkt.flags.qual),
        ),
        ConditionalField(
            BitEnumField("isunixtime", 0, 1, {0: 'the time standard is not defined', 1: 'the time standard is unix time'}),
            lambda pkt: (pkt.flags and pkt.flags.isunixtime),
        ),
        ConditionalField(
            IEEEDoubleField("timeint", 0),
            lambda pkt: (pkt.flags and pkt.flags.time),
        ),
        ConditionalField(
            IEEEDoubleField("timefrac", 0),
            lambda pkt: (pkt.flags and pkt.flags.time),
        ),
        ConditionalField(
            IEEEDoubleField("duration", 0),
            lambda pkt: (pkt.flags and pkt.flags.duration),
        ),
        ConditionalField(
            IEEEDoubleField("lat", 0),
            lambda pkt: (pkt.flags and pkt.flags.location),
        ),
        ConditionalField(
            IEEEDoubleField("lon", 0),
            lambda pkt: (pkt.flags and pkt.flags.location),
        ),
        ConditionalField(
            IEEEDoubleField("alt", 0),
            lambda pkt: (pkt.flags and pkt.flags.location),
        ),
    ]

bind_layers(RFtap, Dot11, dlt=105)
bind_layers(RFtap, Dot15d4FCS, dlt=195)
bind_layers(RFtap, Dot15d4, dlt=230)
