#ifndef _MINIUPNPD_H
#define _MINIUPNPD_H

int discover_ip(int s);
int map_port(int s, int protocol, short prv_port, short pub_port, int lifetime);
int pmp_auth(int s);
int discover_ip_auth(int s);
int map_port_auth(int s, int protocol, short prv_port, short pub_port, int lifetime);

#endif
