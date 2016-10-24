/**************************************
* @author dujiong
* @date 2015.7.22
* @version V1.0
*
* pcap.c ----> parse the frame captured by the usb card and get the rssi, macaddr, frequency...
**************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>

#include "db.h"
#include "pcap.h"

static MYSQL mysql;

#define MAX_ETH_FRAME 2048
#define ERROR_FILE_OPEN_FAILED -1
#define ERROR_MEM_ALLOC_FAILED -2
#define ERROR_PCAP_PARSE_FAILED -3
#define THISAP ".1.196"			

#define MAXLINE  2048
#define MINLINE  256
#define MAC_LEN  6

char buf[MAXLINE], *pos;


// Functions about pcap_file header and pcap header, they are not necessary. So delete it.
// We get the same frame as wireshark displayed.
/*
void printPcapFileHeader(pcap_file_header *pfh){
	if(pfh==NULL)
		return;
	printf(   "magic:0x%0x\n"
  		"version_major:%u\n"
		"version_minor:%u\n"
		"thiszone:%d\n"
		"sigfigs:%u\n"
		"snaplen:%u\n"
		"linktype:%u\n"
		pfh->magic,
		pfh->version_major,
		pfh->version_minor,
		pfh->thiszone,
		pfh->sigfigs,
		pfh->snaplen,
		pfh->linktype	);
}

void printPcapHeader(pcap_header *ph){
	if(ph==NULL)
	{
		return;
	}
	printf( 	"ts.timestamp_s:%u\n"
		"ts.timestamp_ms:%u\n"
		"capture_len:%u\n"
		"len:%d\n"
		ph->ts.timestamp_s,
		ph->ts.timestamp_ms,
		ph->capture_len,
		ph->len);
}
*/

int printPcapBeacon(void* data,size_t size,struct tm * ptrtime, struct timeval t) {		//Beacon Frame

	if(data == NULL)
		return -1;

	unsigned short i=0;
	unsigned short *p = (unsigned short *)data;
	unsigned short ptr[MAC_LEN+1];

	memset(buf, 0, MAXLINE);
	pos = buf;

	for(i=0; i<size/sizeof(unsigned short); i++) {    		
		unsigned short a=ntohs(p[i]);
		if(i%8==0) {
			printf("\n");
		}
		printf("%04x ",a);
	}
	printf("\n");

	unsigned short frequen = ntohs(p[9]);
	unsigned char high, low;
	low = (unsigned char)frequen;
	high = frequen >> 8;
	unsigned short freq;
	freq = low * 16 * 16 + high;
	
	unsigned short b=ntohs(p[11]);      
        	b = b >> 8;
        	char rssi;
	rssi=(char)b;   		
	if(rssi == 0)
		return -1;
	
	sprintf(pos,"insert into ap_rssi values('%u-%02u-%02u %02d:%02d:%02d.%d',",
		1900+ptrtime->tm_year,1+ptrtime->tm_mon,ptrtime->tm_mday,
		ptrtime->tm_hour,ptrtime->tm_min,ptrtime->tm_sec,t.tv_usec);
	pos = buf+strlen(buf);

	sprintf(pos,"'%s',", THISAP);		//the wifi card is located in AP1
	pos = buf+strlen(buf);

	sprintf(pos,"'BEACON',");
	pos = buf+strlen(buf);
		
	memcpy(ptr, p + 18, MAC_LEN); 	
	if(parseMacAddr(ptr) != 0)
		return -1;

	sprintf(pos, "'%d',", freq);
	pos = buf + strlen(buf);

	printf("\nsignal:  %ddbm\n",rssi);
	sprintf(pos,"'%d')",rssi);				

	if(db_tb_insert(buf) != 0)
		exit(0);

	return 0;
}

int printPcapProbReq(void* data,size_t size,struct tm * ptrtime, struct timeval t) {	//Prob Request Frame
	
	if(data == NULL)
		return -1;

	unsigned short i=0;
	unsigned short* p=(unsigned short *)data;	
	unsigned short ptr[MAC_LEN+1];

	memset(buf, 0, MAXLINE);
	pos = buf;

	for(i=0; i<size/sizeof(unsigned short); i++) {    
		unsigned short a=ntohs(p[i]);
		if(i%8==0){
			printf("\n");
		}
		printf("%04x ",a);
	}
	printf("\n");
	
	unsigned short frequen = ntohs(p[9]);
	unsigned char high, low;
	low = (unsigned char)frequen;
	high = frequen >> 8;
	unsigned short freq;
	freq = low * 16 * 16 + high;
	
	unsigned short b=ntohs(p[11]);      
        	b = b >> 8;
        	char rssi;
	rssi=(char)b;   			   //rssi: high 8-bits
	if(rssi == 0)
		return -1;

	sprintf(pos,"insert into sta_rssi values('%u-%02u-%02u %02d:%02d:%02d.%d',",
		1900+ptrtime->tm_year,1+ptrtime->tm_mon,ptrtime->tm_mday,
		ptrtime->tm_hour,ptrtime->tm_min,ptrtime->tm_sec,t.tv_usec);
	pos = buf+strlen(buf);

	sprintf(pos, "'%s',", THISAP);
	pos = buf+strlen(buf);

	sprintf(pos,"'Prob Req',");
	pos = buf+strlen(buf);

	memcpy(ptr, p + 18, MAC_LEN); 	
	if(parseMacAddr(ptr) != 0) 
		return -1;

	sprintf(pos, "'%d',", freq);
	pos = buf + strlen(buf);

	sprintf(pos,"'%d')",rssi);		
	printf("\nsignal:  %ddbm\n",rssi);
	if(db_tb_insert(buf)!=0)
		exit(0);

	return 0;
}

int printPcapNull(void* data,size_t size,struct tm * ptrtime,struct timeval t) {		//Null Function Frame
	
	if(data==NULL){
		return -1;
	}

	unsigned short i=0;
	unsigned short* p=(unsigned short *)data;
	unsigned short ptr[MAC_LEN+1];

	memset(buf,0,MAXLINE);
	pos = buf;
	
	for(i=0;i<size/sizeof(unsigned short);i++){
		unsigned short a=ntohs(p[i]);
		if(i%8==0){
			printf("\n");
		}
		printf("%04x ",a);
	}
	printf("\n");
	
	unsigned short frequen = ntohs(p[9]);
	unsigned char high, low;
	low = (unsigned char)frequen;
	high = frequen >> 8;
	unsigned short freq;
	freq = low * 16 * 16 + high;
	
	unsigned short b=ntohs(p[11]);
        	b = b >> 8;
       	char rssi;
	rssi=(char)b;
        
	sprintf(pos,"insert into sta_rssi values('%u-%02u-%02u %02d:%02d:%02d.%d',",
		1900+ptrtime->tm_year,1+ptrtime->tm_mon,ptrtime->tm_mday,
		ptrtime->tm_hour,ptrtime->tm_min,ptrtime->tm_sec,t.tv_usec);
	pos = buf+strlen(buf);

	sprintf(pos, "'%s',", THISAP);
	pos = buf+strlen(buf);

	sprintf(pos,"'Null Function',");
	pos = buf+strlen(buf);

	memcpy(ptr, p + 18, MAC_LEN); 	
	if(parseMacAddr(ptr) != 0)
		return -1;

	sprintf(pos, "'%d',", freq);
	pos = buf + strlen(buf);
	
	sprintf(pos,"'%d')",rssi);	
	printf("\nsignal:  %ddbm\n",rssi);
	if(db_tb_insert(buf)!=0)
		exit(0);

	return 0;
}

int parseMacAddr(void* data)			
{
	unsigned short* p = (unsigned short*)data;
	char output[MINLINE];
	memset(output, 0, MINLINE);

	unsigned short mac1=ntohs(p[0]);
	unsigned short mac2=ntohs(p[1]);
	unsigned short mac3=ntohs(p[2]);

	unsigned short mach1;
	mach1=mac1 >> 8;
	unsigned char d;
	d=(unsigned char)mac1;
	sprintf(pos,"'%02x:%02x:",mach1,d);
	pos=buf+strlen(buf);
	
	unsigned short mach2;
	mach2=mac2 >> 8;
	unsigned char e;
	e=(unsigned char)mac2;
	sprintf(pos,"%02x:%02x:",mach2,e);
	pos=buf+strlen(buf);
	
	unsigned short mach3;
	mach3=mac3 >> 8;
	unsigned char f;
	f=(unsigned char)mac3;
	sprintf(pos,"%02x:%02x',",mach3,f);
	pos=buf+strlen(buf);

	sprintf(output,"%04x%04x%04x",mac1,mac2,mac3);
	printf("mac address: %s\n", output);
	return 0;
}

int printPcapQos(void* data,size_t size,struct tm * ptrtime, struct timeval t) {  	//Qos Data--->is bidirectional  and has two format   	

	if(data == NULL)
		return -1;

	unsigned short i=0;
	unsigned short* p=(unsigned short *)data;
	unsigned short ptr[MAC_LEN+3];

	memset(buf, 0, MAXLINE);
	pos = buf;

	for(i=0;i<size/sizeof(unsigned short);i++) {   	//print all frame
		unsigned short a=ntohs(p[i]);
		if(i%8==0) {
			printf("\n");
		}
		printf("%04x ",a);
	}
	printf("\n");
	
	unsigned short frequen = ntohs(p[9]);
	unsigned char high, low;
	low = (unsigned char)frequen;
	high = frequen >> 8;
	unsigned short freq;
	freq = low * 16 * 16 + high;
	
	unsigned short b=ntohs(p[11]);
	b = b >> 8;
	char rssi;
	rssi = (char)b;  		 //high 8-bits  --> rssi
	if(rssi >= 0)
		return -1;

	sprintf(pos,"insert into sta_rssi values('%u-%02u-%02u %02d:%02d:%02d.%d',",
		1900+ptrtime->tm_year,1+ptrtime->tm_mon,ptrtime->tm_mday,
		ptrtime->tm_hour,ptrtime->tm_min,ptrtime->tm_sec,t.tv_usec);
	pos = buf+strlen(buf);

	sprintf(pos,"'%s',", THISAP);		//the wifi card is located in AP1(ip address)
	pos = buf+strlen(buf);

	sprintf(pos,"'Qos Data',");
	pos = buf+strlen(buf);

#define FLAGMASK 0x01

/*
 * we only want to get the sta->usb card's rssi, not the AP->usb card's rssi
 * Use the flag that indicates  TO DS or FROM DS
 */
 	unsigned short flags = ntohs(p[13]);
 	unsigned char flag;
 	flag = (unsigned char)flags;
 	flag = flag & FLAGMASK;
 	flags = flags >> 8;
 	unsigned char type;
 	type =(unsigned char)flags;

 	unsigned short types_ = ntohs(p[14]);
	unsigned char type_;
	type_ = (unsigned char)types_;
	unsigned short flags_ = ntohs(p[15]);	
	flags_ = flags_ >> 8;
	unsigned char flag_;
	flag_= (unsigned char)flags_;
	flag_ = flag_ & FLAGMASK;

	if(flag == 0x00 && type == 0x88 ) {
		printf("\nFirst: This Frame is from DS to STA via ap, We dont need it\n");
		return -1;
	}else if(flag == 0x01 && type == 0x88) {		
		memcpy(ptr, p+18, MAC_LEN);
		if(parseMacAddr(ptr) != 0){
			return -1;
		}
		sprintf(pos, "'%d',", freq);
		pos = buf + strlen(buf);
		sprintf(pos,"'%d')",rssi);
		printf("\nsignal: %ddbm\n", rssi);	
		if(db_tb_insert(buf) != 0){
			exit(0);
		}
	}else if(flag_ == 0x00 && type_ == 0x88) {
		printf("\nSecond: This Frame is from DS to STA via ap, We dont need it\n");
		return -1;
	}else if(flag_ == 0x01 && type_ == 0x88) {
		memcpy(ptr, p+19, MAC_LEN+2);
		if(parseMacAddrForQos(ptr) != 0){
			return -1;
		}
		sprintf(pos, "'%d',", freq);
		pos = buf + strlen(buf);
		sprintf(pos,"'%d')",rssi);			
		printf("\nsignal:  %ddbm\n",rssi);
		if(db_tb_insert(buf) != 0){
			exit(0);
		}
	}
	return 0;
}

int parseMacAddrForQos(void* data) {

	unsigned short* p = (unsigned short*)data;
	char output[MAXLINE];
	memset(output, 0, MAXLINE);	

	unsigned short mac1=ntohs(p[0]);
	unsigned short mac2=ntohs(p[1]);
	unsigned short mac3=ntohs(p[2]);
	unsigned short mac4=ntohs(p[3]);

	unsigned char d;
	d=(unsigned char)mac1;  

	unsigned short mach2;
	mach2=mac2 >> 8;
	unsigned char e;
	e=(unsigned char)mac2;

	sprintf(pos,"'%02x:%02x:", d, mach2);
	pos=buf+strlen(buf);
		
	unsigned short mach3;
	mach3=mac3 >> 8;
	unsigned char f;
	f=(unsigned char)mac3;
	sprintf(pos,"%02x:%02x:",e,mach3);
	pos=buf+strlen(buf);
		
	unsigned short mach4;
	mach4=mac4 >> 8;
	sprintf(pos,"%02x:%02x',",f,mach4);
	pos=buf+strlen(buf);

	sprintf(output, "%02x%04x%04x%02x", d, mac2, mac3, mach4);

	printf("mac address: %s\n", output);
	return 0;
}

