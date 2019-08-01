# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) John Mikulskis <jkulskis@bu.edu>
# This program is published under a GPLv2 license

"""
RFT (RFtap RF Protocol).
"""

from scapy.layers.dot11 import Dot11
from scapy.packet import Packet, bind_layers
from scapy.fields import *


class RFtap(Packet):
    name = "RFtap Protocol"
    fields_desc = [
        BitField("magic", 0, 32),
        BitField("length32", 0, 16),
        LEIntField("dlt", 0),
        IEEEFloatField("freq", 0),
        IEEEFloatField("nomfreq", 0),
        IEEEFloatField("freqofs", 0),
        BitEnumField("isdbm", 0, 1, {0: 'power units are dB', 1: 'the power units are dBm'}),
        IEEEFloatField("power", 0),
        IEEEFloatField("noise", 0),
        IEEEFloatField("snr", 0),
        IEEEFloatField("qual", 0),
        BitEnumField("isunixtime", 0, 1, {0: 'the time standard is not defined', 1: 'the time standard is unix time'}),
        IEEEFloatField("timeint", 0),
        IEEEFloatField("timefrac", 0),
        IEEEFloatField("duration", 0),
        IEEEFloatField("lat", 0),
        IEEEFloatField("lon", 0),
        IEEEFloatField("alt", 0),
        # FlagsField("flags", 0, 16, ["dlt", "freq", "nomfreq", "freqofs", "isdbm", "power",
        #                             "noise", "snr", "qual", "isunixtime", "time", "duration", "location",
        #                             "reserved1", "reserved2", "reserved3"])
    ]


bind_layers(RFtap, Dot11)
