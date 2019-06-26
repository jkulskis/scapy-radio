#!/bin/bash

# Copyright (C) Airbus DS CyberSecurity, 2014
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay

scapy_install() {
  python3 setup.py install
}

gr_block_install() {
  orig="$(pwd)"
  cd "$1"
  mkdir -p build
  cd build && cmake -DPythonLibs_FIND_VERSION:STRING="2.7" -DPythonInterp_FIND_VERSION:STRING="2.7" -DCMAKE_PREFIX_PATH=$PYBOMBS_PREFIX/lib/cmake/gnuradio .. && make && sudo make install
  cd "$orig"
}

blocks_install() {
  for d in gnuradio/*; do
    [ "$d" = "/scapy-radio/gnuradio/grc" ] && continue
    gr_block_install "$d"
  done
}

if [ $# -eq 0 ]; then
  scapy_install
  blocks_install
else
  while [ $# -ne 0 ]; do
    case $1 in
      scapy)
	scapy_install
	;;
      blocks)
	blocks_install
	;;
      *)
	echo "Invalid option: $1"
    esac
    shift
  done
fi
