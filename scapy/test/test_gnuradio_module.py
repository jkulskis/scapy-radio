import scapy.modules.gnuradio as gnuradio
from scapy.modules.gnuradio import Radio


def test_set_vars():
    radio = gnuradio.Radio()


def test_radio_init():
    radio = Radio()


def test_specific_radio_init():
    radio = Radio('hackrf')

def test_protocol_modes():
    radio = Radio()
    if radio.protocols:
        print(radio.protocol_modes(radio.protocols[0]))
    else:
        print('Could not find any protocols')

def test_gnuradio_set_vars():
    gnuradio.gnuradio_set_vars(channel=11)

def test_gnuradio_get_vars():
    print('Channel:', gnuradio.gnuradio_get_vars('channel'))

def test_gnuradio_stop_graph():
    gnuradio.gnuradio_stop_graph()

def test_gnuradio_start_graph():
    gnuradio.gnuradio_start_graph()

