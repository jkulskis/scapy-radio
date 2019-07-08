/* -*- c++ -*- */
/* 
 * Copyright 2019 gr-zigbee author.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_ZIGBEE_PREAMBLE_PREFIXER_SCAPY_FUZZER_IMPL_H
#define INCLUDED_ZIGBEE_PREAMBLE_PREFIXER_SCAPY_FUZZER_IMPL_H

#include <zigbee/preamble_prefixer_scapy_fuzzer.h>

namespace gr {
  namespace zigbee {

    class preamble_prefixer_scapy_fuzzer_impl : public preamble_prefixer_scapy_fuzzer
    {
     private:
      std::vector<int> minPreambleBytes;
      std::vector<int> maxPreambleBytes;
      char buf[256];

     public:
      preamble_prefixer_scapy_fuzzer_impl(std::vector<int> minPreambleBytes, std::vector<int> maxPreambleBytes);
      ~preamble_prefixer_scapy_fuzzer_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      void make_frame(pmt::pmt_t msg);
    };

  } // namespace zigbee
} // namespace gr

#endif /* INCLUDED_ZIGBEE_PREAMBLE_PREFIXER_SCAPY_FUZZER_IMPL_H */

