#ifndef COOKIE_HPP
#define COOKIE_HPP
#ifndef COOKIE_H
#define COOKIE_H

void Call_Device(char **C_dev);
int  Pcap_init(char **P_dev, pcap_t **P_handle);
int Lib_init(libnet_t **L_libhandle,char **L_dev);





int flag=0;
int len;
regex_t *compiled;
regmatch_t *matchptr;
size_t nmatch;
char *dev;
regmatch_t pmatch;
regex_t reg;
pcap_t *handle;
libnet_t *lib_handle, *infect_packet;
sqlite3 *db;
const char* data = "Callback function called";
char *zErrMsg = 0;
char* insert_sql = "INSERT INTO moz_cookies VALUES (";
int id = 1;
char * baseDomain= ",'naver.com',' ','";
char * name_h="','";
char * value_cookie_h="',";
char * insert_sql2 = "'.naver.com','/',3046267007,1468430207929792,1468430211263527,0,0,0,0);";
char * value_cookie;
char * name;



void Call_Device(char **C_dev)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char Select_device[10];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    /* Print the list */
    for(d=alldevs;d;d=d->next)
        printf("%d. %s \n", ++i, d->name);

    if(i==0)
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    printf("\nSelect Device: ");
    scanf("%s",&Select_device);

    *C_dev=Select_device;

    /* We don't need any more the device list. Free it */
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





#endif
#endif

