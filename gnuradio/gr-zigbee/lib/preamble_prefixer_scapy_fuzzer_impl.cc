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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "preamble_prefixer_scapy_fuzzer_impl.h"
#include <gnuradio/block_detail.h>

namespace gr {
  namespace zigbee {

    preamble_prefixer_scapy_fuzzer::sptr
    preamble_prefixer_scapy_fuzzer::make(std::vector<int> minPreambleBytes, std::vector<int> maxPreambleBytes)
    {
      return gnuradio::get_initial_sptr
        (new preamble_prefixer_scapy_fuzzer_impl(minPreambleBytes, maxPreambleBytes));
    }

    /*
     * The private constructor
     */
    preamble_prefixer_scapy_fuzzer_impl::preamble_prefixer_scapy_fuzzer_impl(std::vector<int> minPreambleBytes, std::vector<int> maxPreambleBytes)
      : gr::block("preamble_prefixer_fuzzer",
              gr::io_signature::make(0,0,0),
              gr::io_signature::make(0,0,0))
    {
      assert(minPreambleBytes.size() == 5 && maxPreambleBytes.size() == 5);
      this->minPreambleBytes = minPreambleBytes;
      this->maxPreambleBytes = maxPreambleBytes;
      srand (time(NULL));
      for (int ii=0; ii < 5; ii++) {
        if (this->maxPreambleBytes[ii] > 256) {
          this->maxPreambleBytes[ii] = 256;
        }
        else if (this->maxPreambleBytes[ii] < 1) {
          this->maxPreambleBytes[ii] = 1;
        }
        if (this->minPreambleBytes[ii] >= this->maxPreambleBytes[ii]) {
          this->minPreambleBytes[ii] = this->maxPreambleBytes[ii] - 1;
        }
      }
      //Queue stuff
      message_port_register_out(pmt::mp("out"));
      message_port_register_in(pmt::mp("in"));
      set_msg_handler(pmt::mp("in"), boost::bind(&preamble_prefixer_scapy_fuzzer_impl::make_frame, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    preamble_prefixer_scapy_fuzzer_impl::~preamble_prefixer_scapy_fuzzer_impl()
    {
    }

    void
    preamble_prefixer_scapy_fuzzer_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
      ninput_items_required[0] = noutput_items;
    }

    void
    preamble_prefixer_scapy_fuzzer_impl::make_frame (pmt::pmt_t msg)
    {
        if(pmt::is_eof_object(msg)) {
            message_port_pub(pmt::mp("out"), pmt::PMT_EOF);
            detail().get()->set_done(true);
            return;
        }

        buf[0] = rand() % (this->maxPreambleBytes[0] - this->minPreambleBytes[0]) + this->minPreambleBytes[0];
        buf[1] = rand() % (this->maxPreambleBytes[1] - this->minPreambleBytes[1]) + this->minPreambleBytes[1];
        buf[2] = rand() % (this->maxPreambleBytes[2] - this->minPreambleBytes[2]) + this->minPreambleBytes[2];
        buf[3] = rand() % (this->maxPreambleBytes[3] - this->minPreambleBytes[3]) + this->minPreambleBytes[3];
        buf[4] = rand() % (this->maxPreambleBytes[4] - this->minPreambleBytes[4]) + this->minPreambleBytes[4];

        assert(pmt::is_pair(msg));
        pmt::pmt_t blob = pmt::cdr(msg);

        size_t data_len = pmt::blob_length(blob);
        assert(data_len);
        assert(data_len < 256 - 5);

        buf[5] = data_len-8;

        std::memcpy(buf + 6, ((const char*)pmt::blob_data(blob))+8, data_len - 8);

        pmt::pmt_t packet = pmt::make_blob(buf, data_len + 6-8);

        message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
    }

  } /* namespace zigbee */
} /* namespace gr */

