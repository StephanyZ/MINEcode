/*************************************************************************
> File Name: GRE.h
> Author:xfzhang 
> Mail:923036400@qq.com 
> Created Time: 2017年07月11日 星期二 13时37分07秒
************************************************************************/

#ifndef _GRE_H
#define _GRE_H
typedef struct MACHeader_t{
    unsigned char Destin_MAC[6];
    unsigned char Source_MAC[6];
    short Type;       
}MACHeader_t;

typedef struct IPHeader_t{
    char Ver_and_HLen;
    char Type_Of_Service;
    short Len_Of_IPData;//IPhead+IPData
    short Packet_ID;
    short Flag_Segment;
    char TTL;
    char Protocol_Type;
    short Check_Sum;
    int Source_IP;
    int Destin_IP;
}IPHeader_t;

typedef struct UDPHeader_t{
    short Source_port;
    short Destin_port;
    short Len_of_UDPData;//UDPHeader_t+UDPData
}UDPHeader_t;

typedef struct GTP_t{
    char flag;
    char Message_Type;//total-4
    short Len_Of_GTPData;
    int TEID;
}GTP_t;
typedef struct IEHead_t{
    char IE_Type;
    short IE_Len; //Total=4+data
    char Flag;
}IEHead_t;
#endif
