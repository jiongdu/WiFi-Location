/**************************************
* @author dujiong
* @date 2015.7.28
* @version V1.0
*
* dbtest.c ----> handle database.
**************************************/

#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"

static MYSQL mysql;

int db_init(const char* hostIp) {
	
	MYSQL *conn;
	conn = mysql_init(&mysql);

	if(mysql_real_connect(
		conn,hostIp,"root","dujiong","",0,NULL,0)==NULL) {	
			exit(0);
			fprintf(stderr,"No database connections!\n");
			return -1;
	}
	mysql_query(conn,"SET NAMES 'UTF8'");

	if(db_db_create("wireless_info")) {
		return -1;
	}
		
	return 0;
}

int db_db_create(const char *name) {
	
	MYSQL *conn;
	char buf[128];
	int ret;

	conn=&mysql;
	memset(buf,0,128);
	sprintf(buf,"CREATE DATABASE %s",name);

	ret = mysql_query(conn,buf);

	if(ret && (mysql_errno(conn) == ER_DB_CREATE_EXISTS)) {			
		fprintf(stderr,"Drop the existed database!\n");
		memset(buf,0,128);
		sprintf(buf,"use %s",name);
		mysql_query(conn,buf);
	}else {
		memset(buf,0,128);
		sprintf(buf,"use %s",name);
		mysql_query(conn,buf);

		if(db_tb_create("ap_rssi",AP_RSSI_TABLE)) {
			fprintf(stderr,"Create ap_addr table error\n");
			return -1;
		}
		if(db_tb_create("sta_rssi",STA_RSSI_TABLE)) {
			fprintf(stderr,"Create sta_rssi table error\n");
			return -1;
		}
	}
	return 0;		
}

int db_tb_create(const char *tb_name,int whichtb) {
	
	MYSQL *conn;
	char buf[4096];
	char *pos;
	int ret;

	memset(buf,0,4096);
	pos=buf;

	conn=&mysql;

	sprintf(pos,"CREATE TABLE %s ",tb_name);
	pos += strlen(buf);

	switch(whichtb) {
		case AP_RSSI_TABLE:    
			sprintf(pos,"(timestamp varchar(40) not null,"
				"nic_num varchar(8) not null,"	
				"frametype varchar(16) not null,"
				"macaddr varchar(20) not null,"
				"frequency varchar(4) not null,"
				"rssi int not null,"
				"primary key (timestamp)"
				")");
			ret = mysql_query(conn,buf);
			if(ret) {
				fprintf(stderr,"Create table %s error:%s\n", tb_name ,mysql_error(conn));
				return -1;
			}
			break;
		case STA_RSSI_TABLE:			
		   	sprintf(pos,"(timestamp varchar(40) not null,"
				"nic_num varchar(8) not null,"	
				"frametype varchar(16) not null,"
				"macaddr varchar(20) not null,"
				"frequency varchar(4) not null,"
				"rssi int not null,"
				"primary key (timestamp)"
				")");
			ret = mysql_query(conn,buf);
			if(ret) {
				fprintf(stderr,"Create table %s error:%s\n", tb_name ,mysql_error(conn));
				return -1;
			}
			break;
		default:
			fprintf(stderr,"Unkown table type:%d\n",whichtb);
			return -1;
		}

}

int db_tb_insert(char *a) {

	MYSQL *conn;
	char buf[4096];
	char *pos;
	int ret;
	
	pos = buf;
	conn = &mysql;

	sprintf(pos,"%s",a);
	
   	ret = mysql_query(conn,buf);
	if(ret) {
		return mysql_errno(conn);
	}
	return 0;
}

int db_db_drop(const char *name) {
		MYSQL *conn;
		char buf[128];
		int ret;

		conn=&mysql;

		memset(buf,0,128);
		sprintf(buf,"DROP DATABASE %s",name);
		
		ret = mysql_query(conn,buf);
		if(ret) {
			fprintf(stderr,"%s\n",mysql_error(conn));
			return -1;
		}
		return 0;
}

int db_deinit() {

	MYSQL *conn;
	char buf[128];
	int ret;

	conn=&mysql;

	sprintf(buf,"drop database wireless_info");
		
	ret = mysql_query(conn,buf);
	if(ret) {
		fprintf(stderr,"Drop database wireless_info error:%d\n",mysql_errno(conn));
	}
    	mysql_close(conn);
	return 0;
}


