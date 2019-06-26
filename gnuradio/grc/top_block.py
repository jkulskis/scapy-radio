#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Top Block
# GNU Radio version: 3.7.13.5
##################################################

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"

from PyQt4 import Qt
from gnuradio import analog
from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.qtgui import Range, RangeWidget
from math import sin, pi
from optparse import OptionParser
import math
import sys
import time
import zigbee
from gnuradio import qtgui


class top_block(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Top Block")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Top Block")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except:
            pass
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("GNU Radio", "top_block")
        self.restoreGeometry(self.settings.value("geometry").toByteArray())


        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 4000000
        self.channel = channel = 11

        ##################################################
        # Blocks
        ##################################################
        self._channel_range = Range(11, 26, 1, 11, 200)
        self._channel_win = RangeWidget(self._channel_range, self.set_channel, "channel", "counter_slider", float)
        self.top_grid_layout.addWidget(self._channel_win)
        self.zigbee_preamble_prefixer_scapy_0 = zigbee.preamble_prefixer_scapy()
        self.zigbee_packet_sink_scapy_0 = zigbee.packet_sink_scapy(10)
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(('', "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0.set_center_freq(1000000 * (2400 + 5 * (channel - 10)), 0)
        self.uhd_usrp_source_0.set_gain(30, 0)
        self.uhd_usrp_source_0.set_antenna('RX2', 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join(('', "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_samp_rate(samp_rate)
        self.uhd_usrp_sink_0.set_center_freq(1000000 * (2400 + 5 * (channel - 10)), 0)
        self.uhd_usrp_sink_0.set_gain(30, 0)
        self.uhd_usrp_sink_0.set_antenna('TX\\RX', 0)
        self.single_pole_iir_filter_xx_0 = filter.single_pole_iir_filter_ff(0.00016, 1)
        self.digital_clock_recovery_mm_xx_0 = digital.clock_recovery_mm_ff(2, 0.000225, 0.5, 0.03, 0.0002)
        self.digital_chunks_to_symbols_xx_0 = digital.chunks_to_symbols_bc(([(1+1j), (-1+1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (1-1j), (1+1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1+1j), (1+1j), (1-1j), (1+1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1-1j), (-1+1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (1-1j), (1+1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1-1j), (1+1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (1-1j), (1+1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (1-1j), (1+1j), (1-1j), (-1-1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (1-1j), (-1+1j), (1+1j), (-1-1j), (-1-1j), (1+1j), (-1+1j), (-1+1j), (-1-1j), (1-1j), (-1-1j), (1-1j), (1+1j), (1-1j), (1+1j), (-1+1j), (1+1j), (-1-1j), (1-1j), (-1+1j), (-1+1j), (1-1j), (-1-1j), (-1-1j), (-1+1j), (1+1j), (-1+1j), (1+1j), (1-1j), (1+1j), (1-1j), (-1-1j)]), 16)
        self.blocks_vector_source_x_0 = blocks.vector_source_c([0, sin(pi/4), 1, sin(3*pi/4)], True, 1, [])
        self.blocks_sub_xx_0 = blocks.sub_ff(1)
        self.blocks_socket_pdu_0_0_0 = blocks.socket_pdu("UDP_CLIENT", '127.0.0.1', '52002', 10000, False)
        self.blocks_socket_pdu_0 = blocks.socket_pdu("UDP_SERVER", '127.0.0.1', '52001', 10000, False)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_gr_complex*1, 4)
        self.blocks_pdu_to_tagged_stream_0_0_0 = blocks.pdu_to_tagged_stream(blocks.byte_t, 'pdu_length')
        self.blocks_packed_to_unpacked_xx_0 = blocks.packed_to_unpacked_bb(4, gr.GR_LSB_FIRST)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_message_debug_0_0 = blocks.message_debug()
        self.blocks_message_debug_0 = blocks.message_debug()
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_float*1, 2)
        self.blocks_complex_to_float_0 = blocks.complex_to_float(1)
        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf(1)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.blocks_socket_pdu_0, 'pdus'), (self.zigbee_preamble_prefixer_scapy_0, 'in'))
        self.msg_connect((self.zigbee_packet_sink_scapy_0, 'out'), (self.blocks_message_debug_0, 'print_pdu'))
        self.msg_connect((self.zigbee_packet_sink_scapy_0, 'out'), (self.blocks_socket_pdu_0_0_0, 'pdus'))
        self.msg_connect((self.zigbee_preamble_prefixer_scapy_0, 'out'), (self.blocks_message_debug_0_0, 'print_pdu'))
        self.msg_connect((self.zigbee_preamble_prefixer_scapy_0, 'out'), (self.blocks_pdu_to_tagged_stream_0_0_0, 'pdus'))
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.blocks_sub_xx_0, 0))
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.single_pole_iir_filter_xx_0, 0))
        self.connect((self.blocks_complex_to_float_0, 1), (self.blocks_delay_0, 0))
        self.connect((self.blocks_complex_to_float_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.blocks_float_to_complex_0, 1))
        self.connect((self.blocks_float_to_complex_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_multiply_xx_0, 0), (self.blocks_complex_to_float_0, 0))
        self.connect((self.blocks_packed_to_unpacked_xx_0, 0), (self.digital_chunks_to_symbols_xx_0, 0))
        self.connect((self.blocks_pdu_to_tagged_stream_0_0_0, 0), (self.blocks_packed_to_unpacked_xx_0, 0))
        self.connect((self.blocks_repeat_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_sub_xx_0, 0), (self.digital_clock_recovery_mm_xx_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_multiply_xx_0, 0))
        self.connect((self.digital_chunks_to_symbols_xx_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.digital_clock_recovery_mm_xx_0, 0), (self.zigbee_packet_sink_scapy_0, 0))
        self.connect((self.single_pole_iir_filter_xx_0, 0), (self.blocks_sub_xx_0, 1))
        self.connect((self.uhd_usrp_source_0, 0), (self.analog_quadrature_demod_cf_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "top_block")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)
        self.uhd_usrp_sink_0.set_samp_rate(self.samp_rate)

    def get_channel(self):
        return self.channel

    def set_channel(self, channel):
        self.channel = channel
        self.uhd_usrp_source_0.set_center_freq(1000000 * (2400 + 5 * (self.channel - 10)), 0)
        self.uhd_usrp_sink_0.set_center_freq(1000000 * (2400 + 5 * (self.channel - 10)), 0)


def main(top_block_cls=top_block, options=None):

    from distutils.version import StrictVersion
    if StrictVersion(Qt.qVersion()) >= StrictVersion("4.5.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()
    tb.start()
    tb.show()

    def quitting():
        tb.stop()
        tb.wait()
    qapp.connect(qapp, Qt.SIGNAL("aboutToQuit()"), quitting)
    qapp.exec_()


if __name__ == '__main__':
    main()
