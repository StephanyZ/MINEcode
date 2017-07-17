/*************************************************************************
> File Name: search_tid.c
> Author:xfzhang
> Mail:923036400@qq.com
> Created Time: 2017年07月11日 星期二 09时28分31秒
************************************************************************/
#include<stdlib.h>
#include<stdio.h>
#include"GRE.h"
#include<string.h>
#include<arpa/inet.h>
#define N 1024
int main(int argc,char *argv[])
{
    struct MACHeader_t *mac_head;
    struct IPHeader_t *ip_head;
    struct UDPHeader_t *udp_head;
    struct GTP_t *gtp_head;
    struct Head *head;
    struct pcap_file_header *p_file_head;
    struct pcap_header *p_head;
    struct _802_1Q_LAN *lan;
    void copy_stream(FILE*,int,int,char *);
    void print_hex(char *,int);
    void paste_stream(char*,int,FILE*);
    int search_tid_in_Data(FILE *,int,int,int);
    int search_tid_in_head(FILE *);
    FILE *fp,*output;
    if((fp=fopen(argv[1],"r"))==NULL)
    {
        printf("error:can not open file");
        return 0;
    }
    char outfilename[20];
    sprintf(outfilename,"%s.pcap",argv[2]);
    if((output=fopen(outfilename,"w"))==NULL)
    {
        printf("error");
        return 0;
    }
    char *head_buf;
    head_buf=(char*)malloc(24*sizeof(char));
    copy_stream(fp,0,24,head_buf);
    printf(head_buf,24);
    paste_stream(head_buf,24,output);
    fclose(output);
    printf("%s\n",argv[1]);
    int count=0;
    int offset=24;
    char ch;
    char buf[3*N]="";
    p_file_head=(struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
    p_head=(struct pcap_header*)malloc(sizeof(struct pcap_header));
    gtp_head=(struct GTP_t *)malloc(sizeof(struct GTP_t));
    mac_head=(struct MACHeader_t *)malloc(sizeof(struct MACHeader_t));
    ip_head=(struct IPHeader_t *)malloc(sizeof(struct IPHeader_t));
    lan=(struct _802_1Q_LAN *)malloc(sizeof(struct _802_1Q_LAN));
    printf("\n");
    fseek(fp,0,0);
    int TID=atoi(argv[2]);
    //printf("\nTID:%d\n",(unsigned int)ntohl(TID));
    memset(gtp_head, '\0', sizeof(ch));
    fread(p_file_head,24,1,fp);
    offset=24;
    int offset_head=0;
    count=0;
    int Len=0;
    int len_pcap=0;
    int len_gtp=0;
    int tid=0;
    int size;
    int FF=0;
    while(fseek(fp,offset,0)==0)
    {
        offset_head=offset;
        fread(p_head,16,1,fp);
        len_pcap=(unsigned int)p_head->capture_len;
       // printf("len_pcap:%.4x(%d)\n",len_pcap,len_pcap);
        FF=0;
        offset+=16;
        if(fread(mac_head,14,1,fp)!=1)
        {
            printf("pcap end\n");
            return 0;
        }
       /* printf("mac_source:");
        printf("%.2x:",mac_head->Source_MAC[0]);
        printf("%.2x:",mac_head->Source_MAC[1]);
        printf("%.2x:",mac_head->Source_MAC[2]);
        printf("%.2x:",mac_head->Source_MAC[3]);
        printf("%.2x:",mac_head->Source_MAC[4]);
        printf("%.2x\n",mac_head->Source_MAC[5]);
        printf("mac_destin:");
        printf("%.2x:",mac_head->Destin_MAC[0]);
        printf("%.2x:",mac_head->Destin_MAC[1]);
        printf("%.2x:",mac_head->Destin_MAC[2]);
        printf("%.2x:",mac_head->Destin_MAC[3]);
        printf("%.2x:",mac_head->Destin_MAC[4]);
        printf("%.2x\n",mac_head->Destin_MAC[5]);*/
        count++;
        //printf("-------------------------------count:%d\n",count);
        //printf("mac_head->Type:%.2x,%d\n",(unsigned short)ntohs(mac_head->Type),(unsigned short)ntohs(mac_head->Type));
        if((unsigned short)ntohs(mac_head->Type)==0x8100)
        {
           // printf("count %d is catched in type 0x8100\n",count);
            if(fread(lan,8,1,fp)!=1)
            {
                printf("read error in lan\n");
                return 0;
            }
            if((unsigned short)ntohs(lan->Type)==0x0800)
            {
               // printf("lan->Type=%.2x,%d\n",(unsigned short)ntohs(lan->Type),(unsigned short)ntohs(lan->Type));
                offset+=4;
                FF=1;
            }
            else
            {
                printf("there has no deal protocol in count:%d !\n",count);
                return 0;
            }
        }
        else if((unsigned short)ntohs(mac_head->Type)==0x0800)
        {
            FF=1;
        }
        else
        {
            printf("there has no deal protocol in count:%d !\n",count);
            return 0;
        }
        offset+=14;
        fseek(fp,offset,0);
        fread(ip_head,20,1,fp);
       // printf("len_ip_total:%.2x(%d)\n",(unsigned short)ntohs(ip_head->Len_Of_IPData),(unsigned short)ntohs(ip_head->Len_Of_IPData));
        offset+=20+8;
        Len=(unsigned short)ntohs(ip_head->Len_Of_IPData);
       // printf("-------------------------ip_head->Protocol_Type:%d\n",(unsigned char)ip_head->Protocol_Type);
        if(ip_head->Protocol_Type==17)
        {
            fseek(fp,offset,0);
            if(fread(gtp_head,8,1,fp)!=1)
            {
                printf("read end of file");
                return 0;
            }
            fseek(fp,offset,0);
           // printf("1.offset:%d\n",offset);
           // printf("flag:%.2x\n",gtp_head->flag);
           // printf("type:%.2x\n",gtp_head->Message_Type);
           // printf("lenth:%.2x(%d)\n",(unsigned short)ntohs(gtp_head->Len_Of_GTPData),(unsigned short)ntohs(gtp_head->Len_Of_GTPData));
            // Len=(unsigned short)ntohs(ip_head->Len_Of_IPData);
            tid=(unsigned int)ntohl(gtp_head->TEID);
            len_gtp=(unsigned short)ntohs(gtp_head->Len_Of_GTPData);
            offset+=Len-12;
            size=offset-offset_head;
           // printf("-------------------------------count:%d\n",count);
           // printf("Message_Type:%.2x,%d\n",(unsigned char)gtp_head->Message_Type,(unsigned char)gtp_head->Message_Type);
            if((search_tid_in_head(fp)==TID)||((search_tid_in_Data(fp,offset-Len+12+12,len_gtp-8,TID)==1))&&(unsigned char)gtp_head->Message_Type!=0xff)
            {
                printf("-------------------------------catch_count:%d\n",count);
                char *p;
                p=(char *)malloc((offset-offset_head)*sizeof(char));
                copy_stream(fp,offset_head,len_pcap+16,p);
                //print_hex(p,len_pcap+16);
                if((output=fopen(outfilename,"a+"))==NULL)
                {
                    printf("open file failed!");
                    return 0;
                }
                paste_stream(p,len_pcap+16,output);
                fclose(output);
            }
            //printf("tid:%.8x\n",(unsigned int)ntohl(gtp_head->TEID));
            //printf("2.offset:%d\noffset_head:%d\n\n",offset,offset_head);
        }
        else
        {
            if((unsigned char)gtp_head->Message_Type==0xff)
            {
              // printf("-------------------------------------------------Is Data\n");
            }
            offset+=Len-12;
        }
        offset=offset_head+len_pcap+16;
    }
    fclose(fp);
    return 0;
}
void print_hex(char *buf,int size)
{
    printf("\n");
    for(int i=0; i<size; i++)
    {
        printf("%.2x ",(unsigned char)buf[i]);
        if((i+1)%16==0)
        {
            printf("\n");
        }
        else if((i+1)%8==0)
        {
            printf(" ");
        }
    }
    printf("\n");
}
void paste_stream(char *buf,int size,FILE *file)
{
    int file_offset=0;
    file_offset=ftell(file);
    fseek(file,0,SEEK_END);
    fwrite(buf,size,1,file);
   // print_hex(buf,size);
    fseek(file,file_offset,SEEK_SET);
}
void copy_stream(FILE *raw,int offset,int size,char *buf)
{
    int raw_offset=0;
    raw_offset=ftell(raw);
    fseek(raw,offset,SEEK_SET);
   // printf("\nstream size is:%d\n",size);
    for(int i=0; i<size; i++)
    {
        buf[i]=fgetc(raw);
    }
    fseek(raw,raw_offset,SEEK_SET);
}
int search_tid_in_head(FILE *fp)
{
    GTP_t *gtp_head;
    //printf("--------------------TID_offset:%d\n",(int)ftell(fp));
    gtp_head=(struct GTP_t*)malloc(sizeof(struct GTP_t));
    int tid;
    if(fread(gtp_head,8,1,fp)!=1)
    {
        printf("read end of file");
        return -1;
    }
    tid=(unsigned int)ntohl(gtp_head->TEID);
   // printf("-----------------------TID:%.4x\n",tid);
    fseek(fp,ftell(fp)+4,0);
    return tid;
}
int search_tid_in_Data(FILE *fp,int offset,int size,int TID)
{
   // printf("---------offset:%d-----------TID_Data_offset:%d\n",offset,(int)ftell(fp));
    IEHead_t *ie_head;
    typedef struct Tid
    {
        int teid;
    } Tid;
    Tid *tid;
    tid=(struct Tid*)malloc(sizeof(struct Tid));
    int fp_offset=0;
    int cur_offset=0;
    ie_head=(struct IEHead_t*)malloc(sizeof(struct IEHead_t));
    fp_offset=ftell(fp);
    fseek(fp,offset,SEEK_SET);
    cur_offset=offset;
    while((cur_offset-offset)<size)
    {
        fseek(fp,cur_offset,SEEK_SET);
        if(fread(ie_head,4,1,fp)!=1)
        {
            printf("errorr in fread ie_head\n");
            // fseek(fp,fp_offset,SEEK_SET);
            return -1;
        }
       // printf("-----offset_cur:%d------IEtype:%d\n",cur_offset,ie_head->IE_Type);
        if((unsigned char)(ie_head->IE_Type)==87)
        {
            cur_offset+=5;
            fseek(fp,cur_offset,SEEK_SET);
            if(fread(tid,4,1,fp)!=1)
            {
                printf("error in fread IE_type\n");
                //fseek(fp,fp_offset,SEEK_SET);
                return -1;
            }
            //printf("------------------------------DATA_TID:%.4x\n",(unsigned int)ntohl(tid->teid));
            cur_offset-=5;
            fseek(fp,cur_offset,SEEK_SET);
            if((unsigned int)ntohl(tid->teid)==TID)
            {
                // fseek(fp,fp_offset,SEEK_SET);
                return 1;
            }
        }
        if((unsigned char)(ie_head->IE_Type)==93)
        {
            if(search_tid_in_Data(fp,cur_offset+4,(unsigned short)ie_head->IE_Len+4,TID)==1)
            {
                // fseek(fp,fp_offset,SEEK_SET);
                return 1;
            }
        }
        cur_offset+=4+(unsigned short)ie_head->IE_Len;
    }
    fseek(fp,fp_offset,SEEK_SET);
}
