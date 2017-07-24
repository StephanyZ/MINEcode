/*************************************************************************
> File Name: cutpcap.c
> Author:xfzhang
> Mail:923036400@qq.com
> Created Time: 2017年07月24日 星期一 16时35分25秒
************************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include"GRE.h"
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
    int TEID_Is_In(int,int*,int);
    int search_tid_in_Data(FILE *,int,int,int *);
    int search_tid_in_head(FILE *,int *);
    FILE *fp,*output;
    p_file_head=(struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
    p_head=(struct pcap_header*)malloc(sizeof(struct pcap_header));
    gtp_head=(struct GTP_t *)malloc(sizeof(struct GTP_t));
    mac_head=(struct MACHeader_t *)malloc(sizeof(struct MACHeader_t));
    ip_head=(struct IPHeader_t *)malloc(sizeof(struct IPHeader_t));
    lan=(struct _802_1Q_LAN *)malloc(sizeof(struct _802_1Q_LAN));
    if((fp=fopen(argv[1],"r"))==NULL)
    {
        printf("error:can not open file");
        return 0;
    }
    char outfilename[20];
    sprintf(outfilename,"%s",argv[2]);
    if((output=fopen(outfilename,"w"))==NULL)
    {
        printf("error");
        return 0;
    }
    int num1=atoi(argv[3]);
    int num2=atoi(argv[4]);
    int count=0;
    int size=0;
    int offset=24;
    int offset_head=0;
    char *head_buf;
    int len_pcap=0;
    head_buf=(char*)malloc(24*sizeof(char));
    copy_stream(fp,0,24,head_buf);
    paste_stream(head_buf,24,output);
    fclose(output);
    offset=24;
    printf("%d-%d\n",num1,num2);
    while(fseek(fp,offset,0)==0)
    {
        count++;
        offset_head=offset;
        fread(p_head,16,1,fp);
        len_pcap=(unsigned int)p_head->capture_len;
        if(count>=num1&&count<=num2)
        {
            char *p;
            p=(char *)malloc((len_pcap+16)*sizeof(char));
            copy_stream(fp,offset_head,len_pcap+16,p);
            if((output=fopen(outfilename,"a+"))==NULL)
            {
                printf("open file failed!");
                return 0;
            }
            paste_stream(p,len_pcap+16,output);
            fclose(output);
        }
        else if(count>num2)
        {
            break;
        }
        offset=offset_head+len_pcap+16;
    }
    return 0;
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
    //printf("\nstream size is:%d\n",size);
    for(int i=0; i<size; i++)
    {
        buf[i]=fgetc(raw);
    }
    fseek(raw,raw_offset,SEEK_SET);
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
