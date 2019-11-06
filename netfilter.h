#pragma once

uint8_t* HTTP_METHOD[] = {"GET","POST","HEAD","PUT","DELETE","OPTIONS"};

struct IP_HDR{
    uint8_t header;  // 4bit version, next 4bit IP header length
    uint8_t tos;     // type of service
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t ttl;      // time to live
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct TCP_HDR{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_numm;
    uint16_t flag;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

uint8_t* host_url;