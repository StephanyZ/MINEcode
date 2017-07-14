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
int main(int argc,char *argv[]){
    struct MACHeader_t *mac_head;
    struct IPHeader_t *ip_head;
    struct UDPHeader_t *udp_head;
    struct GTP_t *gtp_head;
    struct Head *head;
    void copy_stream(FILE*,int,int,char *);
    void print_hex(char *,int);
    void paste_stream(char*,int,FILE*);
    FILE *fp,*output;
    if((fp=fopen(argv[1],"r"))==NULL){
        printf("error:can not open file");
        return 0;
    }
    char outfilename[20];
    sprintf(outfilename,"%s.pcap",argv[2]);
    if((output=fopen(outfilename,"w"))==NULL){
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
    int offset=40;
    char ch;
    char buf[3*N]="";
    gtp_head=(struct GTP_t *)malloc(sizeof(struct GTP_t));
    mac_head=(struct MACHeader_t *)malloc(sizeof(struct MACHeader_t));
    ip_head=(struct IPHeader_t *)malloc(sizeof(struct IPHeader_t));
    printf("\n");
    fseek(fp,0,0);
    while((ch=fgetc(fp))!=EOF){
        count++;
        printf("%.2x",(unsigned char)ch);   
        if(count%8==0){
            if(count%16==0){
                printf("\n");
            }else{
                printf(" ");
            }
        }
    }
    int TID=atoi(argv[2]);
    printf("\nTID:%d\n",TID);
    memset(gtp_head, '\0', sizeof(ch));
    fseek(fp,40,0);
    offset=40;
    int offset_head=0;
    count=0;
    int Len=0;
    int tid=0;
    while(fseek(fp,offset,0)==0){
        if(fread(mac_head,14,1,fp)!=1){
            printf("error");
            return 0;
        }
        printf("mac_source:");
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
        printf("%.2x\n",mac_head->Destin_MAC[5]);
        count++;
        offset_head=offset;
        offset+=14;
        fseek(fp,offset,0);
        fread(ip_head,20,1,fp);
        printf("len_ip_total:%.2x(%d)\n",(unsigned short)ntohs(ip_head->Len_Of_IPData),(unsigned short)ntohs(ip_head->Len_Of_IPData));
        offset+=20+8;
        fseek(fp,offset,0);
        if(fread(gtp_head,8,1,fp)!=1){
            printf("read end of file");
            return 0;
        }
        printf("1.offset:%d\n",offset);
        printf("flag:%.2x\n",gtp_head->flag);
        printf("type:%.2x\n",gtp_head->Message_Type);
        printf("lenth:%.2x(%d)\n",(unsigned short)ntohs(gtp_head->Len_Of_GTPData),(unsigned short)ntohs(gtp_head->Len_Of_GTPData));
        Len=(unsigned short)ntohs(ip_head->Len_Of_IPData);
        tid=(unsigned int)ntohl(gtp_head->TEID);
        offset+=Len-12;
        if(TID==0){
        }
        if(TID==tid){
            printf("%d----------------yes!\n",count);
            char *p;
            p=(char *)malloc((offset-offset_head)*sizeof(char));
            copy_stream(fp,offset_head-16,offset-offset_head,p);
            print_hex(p,offset-offset_head);
            if((output=fopen(outfilename,"a+"))==NULL){
                printf("open file failed!");
                return 0;
            }
            paste_stream(p,offset-offset_head,output);
            fclose(output);
        }
    printf("tid:%.8x\n",(unsigned int)ntohl(gtp_head->TEID));
    printf("2.offset:%d\noffset_head:%d\n\n",offset,offset_head);
    }
    printf("\ncount:%d\n",count);
    fclose(fp);
    return 0;
}
void print_hex(char *buf,int size){
    printf("\n");
    for(int i=0;i<size;i++){
        printf("%.2x ",(unsigned char)buf[i]);
        if((i+1)%16==0){
            printf("\n");
        }else if((i+1)%8==0){
            printf(" ");
        }
    }
    printf("\n");
}
void paste_stream(char *buf,int size,FILE *file){
    int file_offset=0;
    file_offset=ftell(file);
    fseek(file,0,SEEK_END);
    fwrite(buf,size,1,file);
    print_hex(buf,size);
    fseek(file,file_offset,SEEK_SET);
}
void copy_stream(FILE *raw,int offset,int size,char *buf){
    int raw_offset=0;
    raw_offset=ftell(raw);
    fseek(raw,offset,SEEK_SET);
    printf("\nstream size is:%d\n",size);
    for(int i=0; i<size; i++){
        buf[i]=fgetc(raw);   
    }
    fseek(raw,raw_offset,SEEK_SET);
}
int search_tid_in_head(FILE *fp){
    GTP_t *gtp_head;
    gtp_head=(struct GTP_t*)malloc(sizeof(struct GTP_t));
    int tid;
    if(fread(gtp_head,8,1,fp)!=1){
        printf("read end of file");
        return -1;
    }  
    tid=(unsigned int)ntohl(gtp_head->TEID);
    return tid;
}
int search_tid_in_Data(FILE *fp,int offset,int size,int TID){
    IEHead_t *ie_head;
    int tid;
    int fp_offset=0;
    int cur_offset=0;
    ie_head=(struct IEHead_t*)malloc(sizeof(struct IEHead_t));
    fp_offset=ftell(fp);
    fseek(fp,offset,SEEK_SET);
    cur_offset=offset;
    if(TID==search_tid_in_head(fp)){
        return 1;
    }else{
        cur_offset+=12;
        while((cur_offset-offset)<size){
            fseek(fp,cur_offset,SEEK_SET);
            if(fread(ie_head,4,1,fp)!=1){
                printf("errorr in fread ie_head\n");
                return -1;
            }
            if((unsigned char)(ie_head->IE_Type)==87){
                if(fread(tid,4,1,fp))
            }
            cur_offset+=4+ie_head->IE_Len;
        }
    }
}
