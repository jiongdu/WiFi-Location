/**************************************
* @author dujiong
* @date 2015.7.22
* @version V1.0
**************************************/

#ifndef PCAP_H
#define PCAP_H

#include <unistd.h>
#include <time.h>

typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef int bpf_int32;

typedef struct pcap_file_header{		//pcap_file header
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;
	bpf_u_int32 sigfigs;
	bpf_u_int32 snaplen;
	bpf_u_int32 linktype;
}pcap_file_header;

typedef struct timestamp{
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;
}timestamp;

typedef struct pcap_header{			//pcap header
	timestamp ts;
	bpf_u_int32 capture_len;
	bpf_u_int32 len;
}pcap_header;

int parseMacAddr(void* data);	
int parseMacAddrForQos(void* data);
int printPcapQos(void* data,size_t size,struct tm * ptrtime, struct timeval t);
int printPcapProReq(void* data,size_t size,struct tm * ptrtime, struct timeval t); 
int printPcapNull(void* data,size_t size,struct tm * ptrtime,struct timeval t);
int printPcapBeacon(void* data,size_t size,struct tm * ptrtime, struct timeval t);

#endif
