/*
 * nat-pmp-client.c - A simple NAT-PMP protocol client.
 *
 * Includes example code for an authentication extension for NAT-PMP called
 * NAT-PMP-Auth.
 *
 * NAT-PMP-Auth - Final project of Arthur Taylor and Paul Dittaro for Computer
 * Science 466 - University of Victoria, Spring 2013.
 *
 * All code is original work (as of April 2013) of Arthur Taylor
 * Copyright 2013 Arthur Taylor
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 */

#ifdef MINIUPNPD
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <poll.h>
#include <time.h>
#include <gcrypt.h>
 
/* The GPL Trojan horse. */
#include <readline/readline.h>

#include "rtpp_mupnpd.h"

extern char *secret ;
extern int mupnpfd;

/* Keep track of the expected lifespan of the auth session */
static time_t auth_time = 0;

/* The auth session cipher. */
static gcry_cipher_hd_t cipher;

/* This last received server response timestamp. */
static uint32_t last_timestamp;

/*
 * do_request() - Issue a NAT-PMP request and receive a reply.
 *
 * s - FD of the socket
 * req - Pointer to the buffer of the request packet.
 * req_len - Length of the request packet.
 * resp - Pointer to a buffer which will receive the response.
 * resp_buf_len - Total length of the receiving buffer.
 * return negative values for errors, otherwise it returns the number of bytes
 * in the response.
 */
static int do_request(int s, unsigned char *req, size_t req_len, unsigned char *resp, size_t resp_buf_len) {
	int retry_count;
	int poll_result;
	int resp_len;
	short resp_code;
	struct pollfd pfd[1];

	pfd[0].fd = s;
	pfd[0].events = POLLIN;

	for (retry_count = 0; retry_count < 4; retry_count++) {
		if (send(s, req, req_len, 0) < 0) {
			fprintf(stderr, "Failed to send request.\n");
			return -6;
		}

		/* Wait for a response within 5 seconds. */
		if ((poll_result = poll(pfd, 1, 5000)) < 0) {
			printf("poll failed.\n");
			return -6;
		}

		/* Didn't get a response, try again. */
		if (poll_result == 0)
			continue;

		resp_len = recv(s, resp, resp_buf_len, 0);

		/* Check that the packet is large enough, is the same version
		 * and has the correct responsed code. */
		if (resp_len < 4 ||
			resp[0] != req[0] ||
			resp[1] != req[1] + 128) {
			printf("Invaid response.\n");
			return -6;
		}

		last_timestamp = ntohl(*((uint32_t*)&resp[4]));
		resp_code = ntohs(*((uint16_t*)&resp[2]));

		/* Check the response code from the server. */
		switch (resp_code) {
			case 0:
			return resp_len;

			case 1:
			printf("Result code: Unsupported version\n");
			break;

			case 2:
			printf("Result code: Not authorized or refused\n");
			break;

			case 3:
			printf("Result code: Network failure\n");
			break;

			case 4:
			printf("Result code: Out of resources\n");
			break;

			case 5:
			printf("Result code: Unsupported operation code.\n");
			break;

			default:
			printf("Unknown response code.\n");
			return -6;

		}

		return -resp_code;
	}

	printf("Request times out after 4 retries.\n");
	return -7;
}

/*
 * discover_ip() - Perform a NAT-PMP public IP lookup.
 *
 * s - FD of the socket.
 * returns 0 on succes, -1 on failure.
 */
int discover_ip(int s) {
	unsigned char req[2];
	unsigned char resp[16];
	int resp_len;

	req[0] = 0; /* Version code */
	req[1] = 0; /* Op code, Public Address request */
	req[2] = 0; /* Reserved = 0 */
	req[3] = 0; /* Reserved = 0 */

	if ((resp_len = do_request(s, req, sizeof(req), resp, sizeof(resp))) < 0) {
		return -1;
	}

	fprintf(stderr,"Public IP %d.%d.%d.%d\n", resp[8], resp[9], resp[10], resp[11]);

	return 0;
}

/*
 * map_port() - Perform a NAT-PMP port map.
 *
 * s - FD of the socket
 * protocol - integer, 1 = UDP, 2 = TCP
 * prv_port - The private port of the map.
 * pub_port - The public port of the map.
 * lifetime - The mapping lifetime.
 * returns 0 on success, -1 on failure.
 */
int map_port(int s, int protocol, short prv_port, short pub_port, int lifetime) {
	unsigned char req[12];
	unsigned char resp[16];
	int resp_len;
	
	req[0] = 0; 		/* Version code */
	req[1] = protocol;	/* Op code, 1 = UDP port map, 2 = TCP port map */
	req[2] = 0;		/* Reserved = 0 */
	req[3] = 0;		/* Reserved = 0 */

	*((uint16_t*)(&req[4])) = htons(prv_port);
	*((uint16_t*)(&req[6])) = htons(pub_port);
	*((uint32_t*)(&req[8])) = htonl(lifetime);

	if ((resp_len = do_request(s, req, sizeof(req), resp, sizeof(resp))) < 0) {
		return -1;
	}

	printf("Mapped private port %u to public port %u for %u seconds.\n",
		ntohs(*((uint16_t*)&resp[8])), ntohs(*((uint16_t*)&resp[10])), ntohl(*((uint32_t*)&resp[12])));

	return 0;
}

/*
 * pmp_auth() - Perform a NAT-PMP-AUTH handshake.
 *
 * This uses the NAT-PMP-AUTH secret value stored in a global variable.
 *
 * s - FD of the socket.
 * return 0 on success, -1 on failure.
 */
int pmp_auth(int s) {
	unsigned char req[64];
	unsigned char resp[64];
	unsigned char iv[16];   /* Initization vector (server picks) */
	unsigned char nonce[16]; /* Nonce (we pick) */
	int resp_len;

	if (secret == NULL) {
		fprintf(stderr, "No secret key given!\n");
		return -1;
	}

	/* Authentication part one. See if server supports NAT-PMP-Auth and
	 * receive the current initialization vector. */
	
	req[0] = 0;	/* Version code */
	req[1] = 16;	/* Op code, start auth */
	req[2] = 0; 	/* Reserved = 0 */
	req[3] = 0;	/* Reserved = 0 */

	if ((resp_len = do_request(s, req, 4, resp, sizeof(resp))) < 24) {
		fprintf(stderr, "Server probably does not support NAT-PMP-Auth\n");
		return -1;
	}

	/* Copy the server's IV */
	memcpy(iv, &resp[8], 16);

	/* Authentication part two. Establish cipher and mutual trust. */

	req[0] = 0;	/* Version code */
	req[1] = 17;	/* Op code, complete auth */
	req[2] = 0;	/* Reserved = 0 */
	req[3] = 0;	/* Reserved = 0 */

	/* Pick a nonce */
	gcry_create_nonce(nonce, 16);
	memcpy(&req[4], nonce, 16);
	memcpy(&req[20], nonce, 16);

	/* Open the cipher */
	if (gcry_cipher_open(&cipher, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, 0)) {
		fprintf(stderr, "Failed to create cipher\n");
		return -1;
	}

	if (gcry_cipher_setkey(cipher, secret, strlen(secret))) {
		fprintf(stderr, "Failed to set cipher key\n");
		goto close_cipher_exit_fail;
	}

	if (gcry_cipher_setiv(cipher, iv, 16)) {
		fprintf(stderr, "Failed to set cipher IV\n");
		goto close_cipher_exit_fail;
	}

	if (gcry_cipher_encrypt(cipher, &req[20], 16, NULL, 0)) {
		fprintf(stderr, "Failed to encrypt nonce.\n");
		goto close_cipher_exit_fail;
	}

	/* Send nonce to server */
	if ((resp_len = do_request(s, req, 36, resp, sizeof(resp))) < 40) {
		goto close_cipher_exit_fail;
	}

	/* Decrypt the server's nonce back. */
	if (gcry_cipher_decrypt(cipher, &resp[24], 16, NULL, 0)) {
		fprintf(stderr, "Failed to decrypt server response.\n");
		goto close_cipher_exit_fail;
	}

	if (memcmp(&resp[8], &resp[24], 16)) {
		fprintf(stderr, "Bad response from server.\n");
		goto close_cipher_exit_fail;
	}

	/* If we are here, everything set up correctly and we trust the
	 * server. */

	printf("Auth session initialized.\n");

	auth_time = time(NULL);

	return 0;

close_cipher_exit_fail:
	gcry_cipher_close(cipher);
	return -1;
}

/*
 * discover_ip_auth() - Perform a NAT-PMP-AUTH public IP lookup.
 *
 * s - FD of the socket.
 * returns 0 on succes, -1 on failure.
 */
int discover_ip_auth(int s) {
	unsigned char req[20];
	unsigned char resp[24];
	size_t resp_len;

	/* Check to see if the authenticated session should still be good. */
	if (time(NULL) - auth_time > 5) {
		if (pmp_auth(s))
			return -1;
	}

	/* If we are here the cipher has already been set up. */
	req[0] = 0;	/* Version code */
	req[1] = 18;	/* Op code, enciphered request */
	req[2] = 0; 	/* Reserved = 0 */
	req[3] = 0;	/* Reserved = 0 */

	req[4] = 0; /* Discover IP Op Code */
	req[5] = 0; /* reserved */
	*((uint32_t*)(&req[6])) = htonl(last_timestamp);
	gcry_create_nonce(&req[10], 10);

	if (gcry_cipher_encrypt(cipher, &req[4], 16, NULL, 0)) {
		fprintf(stderr, "Failed to encrypt message.\n");
		gcry_cipher_close(cipher);
		return -1;
	}

	if ((resp_len = do_request(s, req, 20, resp, sizeof(resp))) < 24) {
		gcry_cipher_close(cipher);
		return -1;
	}

	if (gcry_cipher_decrypt(cipher, &resp[8], 16, NULL, 0)) {
		fprintf(stderr, "Failed to decrypt response");
		gcry_cipher_close(cipher);
		return -1;
	}

	if (resp[8] != 128 || resp[9] != 0)
		return -1;

	printf("Success. Response: %d.%d.%d.%d \n", resp[10], resp[11], resp[12], resp[13]);

	return 0;
}

/*
 * map_port_auth() - Perform a NAT-PMP-AUTH port map.
 *
 * s - FD of the socket
 * protocol - integer, 1 = UDP, 2 = TCP
 * prv_port - The private port of the map.
 * pub_port - The public port of the map.
 * lifetime - The mapping lifetime.
 * returns 0 on success, -1 on failure.
 */

int map_port_auth(int s, int protocol, short prv_port, short pub_port, int lifetime) {
	unsigned char req[20];
	unsigned char resp[24];
	size_t resp_len;

	/* Check to see if the authenticated session should still be good. */
	if (time(NULL) - auth_time > 5) {
		if (pmp_auth(s))
			return -1;
	}

	req[0] = 0; 	/* Version code */
	req[1] = 18;	/* Encrypted data code */
	req[2] = 0;	/* Reserved = 0 */
	req[3] = 0;	/* Reserved = 0 */

	req[4] = protocol;
	req[5] = 0;

	*((uint32_t*)(&req[6])) = htonl(last_timestamp);
	*((uint16_t*)(&req[10])) = htons(prv_port);
	*((uint16_t*)(&req[12])) = htons(pub_port);
	*((uint32_t*)(&req[14])) = htonl(lifetime);
	gcry_create_nonce(&req[18], 6);

	if (gcry_cipher_encrypt(cipher, &req[4], 16, NULL, 0)) {
		fprintf(stderr, "Failed to encrypt message.\n");
		gcry_cipher_close(cipher);
		return -1;
	}

	if ((resp_len = do_request(s, req, sizeof(req), resp, sizeof(resp))) < 24) {
		gcry_cipher_close(cipher);
		return -1;
	}

	if (gcry_cipher_decrypt(cipher, &resp[8], 16, NULL, 0)) {
		fprintf(stderr, "Failed to decrypt response");
		gcry_cipher_close(cipher);
		return -1;
	}

	switch (resp[9]) {
		case 0:
		printf("Success. Response: private port %u to public port %u for %u seconds.\n",
			ntohs(*((uint16_t*)&resp[10])), ntohs(*((uint16_t*)&resp[12])), ntohl(*((uint32_t*)&resp[14])));
		return 0;

		case 1:
		printf("Result code: Unsupported version\n");
		break;

		case 2:
		printf("Result code: Not authorized or refused\n");
		break;

		case 3:
		printf("Result code: Network failure\n");
		break;

		case 4:
		printf("Result code: Out of resources\n");
		break;

		case 5:
		printf("Result code: Unsupported operation code.\n");
		break;

		default:
		printf("Unknown response code.\n");
		return -6;
	}

	return -resp[9];
}
#endif
