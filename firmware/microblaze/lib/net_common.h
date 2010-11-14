/* -*- c++ -*- */
/*
 * Copyright 2009,2010 Ettus Research LLC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef INCLUDED_NET_COMMON_H
#define INCLUDED_NET_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <net/socket_address.h>
#include <net/eth_mac_addr.h>

typedef void (*udp_receiver_t)(struct socket_address src, struct socket_address dst,
			       unsigned char *payload, int payload_len);

void register_mac_addr(const eth_mac_addr_t *mac_addr);

void register_ip_addr(const struct ip_addr *ip_addr);

void register_udp_listener(int port, udp_receiver_t rcvr);

void send_udp_pkt(int src_port, struct socket_address dst,
		  const void *buf, size_t len);

void handle_eth_packet(uint32_t *p, size_t nlines);

void send_gratuitous_arp(void);

#endif /* INCLUDED_NET_COMMON_H */
