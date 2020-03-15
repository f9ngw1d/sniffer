#include "package.h"	
#include <iostream>
using namespace std;

MYSQL conn;
void  connection ()
{

	const char *server="localhost";
    const char *user="root";
    const char *password="";
    const char *database="n161002106"; 
	mysql_init(&conn);
	if(!mysql_real_connect(&conn,server,user,password,database,0,NULL,0))
	{
		printf("%s\n", mysql_error(&conn));
	}
	else
	{
		printf("connected..\n");
	}	
}
int SaveRequestInfo(RequestInfo *req)
{
    // 把一个RequestInfo对象入库 返回id
    // -1代表失败
    // id自动填充到传入的req
    
    MYSQL_RES *res;
    MYSQL_ROW row;
    int id;
    char query[200];
    int t,r;
    char str[2];
	sprintf(str,"%d",req->type);
	sprintf(query,"insert into request_infos(src,dest)values(");
	strcat(query,"\"");
	strcat(query,req->src);
	strcat(query,"\"");
	strcat(query,",");
	strcat(query,"\"");
	strcat(query,req->dest);
	strcat(query,"\"");
	strcat(query,")");
	printf("%s\n",query);
	t=mysql_query(&conn,query);
	if(t)
	{
    	printf("Error:%s\n",mysql_error(&conn));
    	return -1;
	}
	else
	{
    	printf("success insert\n");
	}
	char find_id[200];
	sprintf(find_id,"select last_insert_id()");
	r=mysql_query(&conn,find_id);
	if(r)
	{
		printf("Error:%s\n",mysql_error(&conn));
		return -1;
	}
	else
	{
		res=mysql_store_result(&conn);
		if(res)
		{
			row=mysql_fetch_row(res);
			printf("%s\n",row[0]);
			id=atoi(row[0]);
			req->id=id;
		}
		mysql_free_result(res);
	}
	return id;
	    
};


int SaveRequestHeader(RequestHeader * h){
    // 把一个RequestHeader对象入库 返回id
    // -1代表失败
    // id自动填充到传入的req
    
    MYSQL_RES *res;
    MYSQL_ROW row;
    char query[200];
    int t,r;
    int id;

	char str[2];
	sprintf(str,"%d",h->request_id);
	sprintf(query,"insert into request_headers(request_id,header_key,header_value)values(");
	strcat(query,str);
	strcat(query,",");
	strcat(query,"\"");
	strcat(query,h->header_key);
	strcat(query,"\"");
	strcat(query,",");
	strcat(query,"\"");
	strcat(query,h->header_value);
	strcat(query,"\"");
	strcat(query,")");
	printf("%s\n",query);
	t=mysql_query(&conn,query);
	if(t)
	{
	    cout<<"Error:"<<mysql_error(&conn);
	}
	else
	{
	   cout<<t<<endl;
	}
    
	char find_id[200];
	sprintf(find_id,"select last_insert_id()");
	r=mysql_query(&conn,find_id);
	if(r)
	{
		printf("Error:%s\n",mysql_error(&conn));
		return -1;
	}
	else
	{
		res=mysql_store_result(&conn);
		if(res)
		{
		  
			row=mysql_fetch_row(res);
			printf("%s\n",row[0]);
			id=atoi(row[0]);
			h->id=id;
				
		}
	mysql_free_result(res);
	}
	return id;
};