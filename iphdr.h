#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t h_v;
    uint8_t tos;
    uint16_t t_len;
    uint16_t t_id;
    uint16_t f_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    Ip src;
    Ip dst;
    uint32_t sip()
    {
        return ntohl(src);
    }
    uint32_t dip()
    {
        return ntohl(dst);
    }
    uint16_t tlen()
    {
        return ntohs(t_len);
    }
    static uint16_t calcChecksum(IpHdr* ipHdr){
        uint32_t res = 0;
        uint16_t *p;

        // Add ipHdr buffer as array of uint16_t
        p = reinterpret_cast<uint16_t*>(ipHdr);
        for (int i = 0; i < int(sizeof(IpHdr)) / 2; i++) {
            res += ntohs(*p);
            p++;
        }

        // Do not consider padding because ip header length is always multilpe of 2.

        // Decrease checksum from sum
        res -= ntohs(ipHdr->checksum);

        // Recalculate sum
        while (res >> 16) {
            res = (res & 0xFFFF) + (res >> 16);
        }
        res = ~res;

        return uint16_t(res);
    }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)

