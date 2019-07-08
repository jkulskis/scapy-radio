#!/bin/bash

# Copyright (C) Airbus DS CyberSecurity, 2014
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay

pybombs_prefix=/pybombs

scapy_install() {
  cd scapy
  sudo python3 setup.py install
  cd ..
}

grc_install() {
  mkdir -p "${HOME}/.scapy/radio/"

  for i in gnuradio/grc/*.grc; do
    mkdir -p "${HOME}/.scapy/radio/$(basename ${i} .grc)"
    cp "${i}" "${HOME}/.scapy/radio/"
    grcc --directory="${HOME}/.scapy/radio/$(basename ${i} .grc)" "${i}"
  done
}

gr_block_install() {
  orig="$(pwd)"
  cd "$1"
  rm -rf build
  mkdir -p build
  cd build && cmake -DCMAKE_PREFIX_PATH="$pybombs_prefix" .. && make
  sudo make install
  cd "$orig"
}

blocks_install() {
  for d in gnuradio/*; do
    [ "$d" = "gnuradio/grc" ] && continue
    gr_block_install "$d"
  done
}

if [ $# -eq 0 ]; then
  scapy_install
  blocks_install
else
    case $1 in
      scapy)
	scapy_install
	;;
      grc)
	grc_install
	;;
      blocks)
	if [ $# -eq 2 ]
  	  then
    	    pybombs_prefix="$2"
	fi
	blocks_install
	;;
      *)
	echo "Invalid option: $1"
    esac
fi
