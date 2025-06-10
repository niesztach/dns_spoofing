#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SIZE 512

// DNS header structure (bez bit‐fields dla prostoty)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Zamienia etykiety DNS (3www6google3com0) na string "www.google.com"
void decode_name(unsigned char *buf, unsigned char *ptr, char *out) {
    int jumped = 0, len = 0, n;
    char name[256] = {0};
    while ((n = ptr[0])) {
        if ((n & 0xC0) == 0xC0) { // pointer
            int offset = ((n & 0x3F) << 8) | ptr[1];
            ptr = buf + offset;
            continue;
        }
        memcpy(name + len, ptr+1, n);
        len += n;
        name[len++] = '.';
        ptr += n+1;
    }
    name[len-1] = 0;
    strcpy(out, name);
}

// Buduje prostą odpowiedź A-record
int build_response(unsigned char *req, int req_len, unsigned char *res, const char *spoof_domain, const char *spoof_ip) {
    struct DNSHeader *hdr = (struct DNSHeader*) req;
    struct DNSHeader *rh  = (struct DNSHeader*) res;
    memcpy(res, req, sizeof(struct DNSHeader));          // skopiuj ID i część pól
    rh->flags = htons(0x8180);                           // standard response, no error
    rh->ancount = htons(1);                              // 1 answer
    unsigned char *qname = req + sizeof(*hdr);
    unsigned char *rptr  = res + req_len;

    // skopiuj pytanie (QNAME + QTYPE + QCLASS)
    int qsize = req_len - sizeof(*hdr);
    memcpy(res + sizeof(*hdr), qname, qsize);

    // answer: wskazanie do QNAME (pointer 0xC00C)
    unsigned char ans[16];
    int offset = 0;
    ans[offset++] = 0xC0;
    ans[offset++] = sizeof(*hdr);        // 0x0c = wskazuje na pocz. QNAME
    ans[offset++] = 0x00; ans[offset++] = 0x01; // TYPE=A
    ans[offset++] = 0x00; ans[offset++] = 0x01; // CLASS=IN
    ans[offset++] = 0x00; ans[offset++] = 0x00; ans[offset++] = 0x00; ans[offset++] = 0x3C; // TTL=60s
    ans[offset++] = 0x00; ans[offset++] = 0x04; // RDLENGTH=4
    // RDATA = IPv4
    inet_pton(AF_INET, spoof_ip, ans+offset);
    offset += 4;

    memcpy(rptr, ans, offset);
    return sizeof(*hdr) + qsize + offset;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s SPOOF_DOMAIN SPOOF_IP\n", argv[0]);
        return 1;
    }
    const char *target_dom = argv[1];
    const char *target_ip  = argv[2];

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in srv = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = INADDR_ANY };
    bind(sock, (struct sockaddr*)&srv, sizeof(srv));

    unsigned char buf[BUF_SIZE], resp[BUF_SIZE];
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);

    while (1) {
        int n = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr*)&cli, &len);
        if (n < sizeof(struct DNSHeader)) continue;

        // dekoduj nazwę
        char qname[256];
        decode_name(buf, buf + sizeof(struct DNSHeader), qname);

        int resp_len;
        if (strcmp(qname, target_dom) == 0) {
            // od razu zwróć fałszywą odpowiedź
            resp_len = build_response(buf, n, resp, target_dom, target_ip);
            sendto(sock, resp, resp_len, 0, (struct sockaddr*)&cli, len);
            continue;  // zapobiega przekierowaniu do 8.8.8.8
        } else {
            // forward do publicznego DNS (np. 8.8.8.8) i odeślij odpowiedź
            struct sockaddr_in upstream = { .sin_family = AF_INET, .sin_port = htons(53) };
            inet_pton(AF_INET, "8.8.8.8", &upstream.sin_addr);
            sendto(sock, buf, n, 0, (struct sockaddr*)&upstream, sizeof(upstream));
            int m = recvfrom(sock, resp, BUF_SIZE, 0, NULL, NULL);
            sendto(sock, resp, m, 0, (struct sockaddr*)&cli, len);
        }
    }
    close(sock);
    return 0;
}
