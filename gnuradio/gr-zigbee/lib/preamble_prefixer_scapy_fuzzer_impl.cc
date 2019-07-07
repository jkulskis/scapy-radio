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
#include <string.h>
#include <time.h>
#include <gnuradio/block_detail.h>

namespace gr {
  namespace zigbee {

    preamble_prefixer_scapy_fuzzer::sptr
    preamble_prefixer_scapy_fuzzer::make(int octet1, int octet2, int octet3, int octet4, int octet5)
    {
      return gnuradio::get_initial_sptr
        (new preamble_prefixer_scapy_fuzzer_impl(octet1, octet2, octet3, octet4, octet5));
    }

    /*
     * The private constructor
     */
    preamble_prefixer_scapy_fuzzer_impl::preamble_prefixer_scapy_fuzzer_impl(int octet1, int octet2, int octet3, int octet4, int octet5)
      : gr::block("preamble_prefixer_fuzzer",
              gr::io_signature::make(0,0,0),
              gr::io_signature::make(0,0,0))
    {
        srand (time(NULL));
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        buf[4] = 0xA7;
        this->octet1 = octet1;
        this->octet2 = octet2;
        this->octet3 = octet3;
        this->octet4 = octet4;
        this->octet5 = octet5;

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
        printf("Octet 1: %d\n",octet1);
        printf("Octet 2: %d\n",octet2);
        printf("Octet 3: %d\n",octet3);
        printf("Octet 4: %d\n",octet4);
        printf("Octet 5: %d\n",octet5);
        // buf[0] = octet1;
        // buf[1] = octet2;
        // buf[2] = octet3;
        // buf[3] = octet4;
        // buf[4] = octet5;
        if(octet1) {
          buf[0] = rand()%octet1;
        }     
        else {
          buf[0] = 0;
        }
        if(octet2) {
          buf[1] = rand()%octet2;
        }     
        else {
          buf[1] = 0;
        }
        if(octet3) {
          buf[2] = rand()%octet3;
        }     
        else {
          buf[2] = 0;
        }
        if(octet4) {
          buf[3] = rand()%octet4;
        }     
        else {
          buf[3] = 0;
        }
        if(octet5) {
          buf[4] = rand()%octet5;
        }     
        else {
          buf[4] = 0;
        }
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

