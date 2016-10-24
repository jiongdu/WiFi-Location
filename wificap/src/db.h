/**************************************
* @author dujiong
* @date 2015.7.28
* @version V1.0
**************************************/

#ifndef DB_H
#define DB_H

#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>

#define AP_RSSI_TABLE 1
#define STA_RSSI_TABLE 2

int db_init();
int db_db_create(const  char *name);
int db_db_drop(const char *name);
int db_tb_create(const char *tb_name,int whichtb);
int db_tb_insert(char *a);
int db_deinit();

#endif
