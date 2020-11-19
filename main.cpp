#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <string.h>
#include <stdio.h>

using namespace std;

void printLine() {
    cout<<"-----------------------------------------------"<<endl;
}

void printByHexData(u_int8_t *printArr, int length) {
    for(int i=0;i<length;i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";

    }

    cout<<dec<<endl;
    printLine();
}

bool maccmp(uint8_t* a, uint8_t* b, int size) {
  for(int i=0; i<size; i++){
    if(a[i] != b[i]){
      return false;
    }
  }
  return true;
}

int main(int argc, char* argv[]) {
    char* device = argv[1];
    cout << device << endl;

    uint8_t mac[6] = {0x00, 0x0c, 0x29, 0xd6, 0x99, 0x0d};

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcd =  pcap_open_live(device, BUFSIZ,1, 200, errbuf);

    struct pcap_pkthdr *hdr;
    const u_char* pkt_data;
    uint8_t* packet;

    int value_of_next_ex;

      while(true) {
          value_of_next_ex = pcap_next_ex(pcd,&hdr,&pkt_data);

          switch (value_of_next_ex) {
              case 1:
                  //do something with pkt_data and hdr
                  printByHexData((uint8_t*)pkt_data, hdr->len);

                  memcpy(packet, (uint8_t*)pkt_data, hdr->len);

                  // packet[0] = 0x00;
                  // packet[1] = 0x50;
                  // packet[2] = 0x56;
                  // packet[3] = 0xf7;
                  // packet[4] = 0xb3;
                  // packet[5] = 0x9a;

                  // if(packet[23] == 0x01 && packet[34] == 0x08) {
                  //   printf("it's ICMP packet that is ping request.\n");
                  //   // if(maccmp(mac, packet, 6)){
                  //   //   printf("mac address is CORRECT!!!!!!\n");
                  //   // }
                  // }
                  cout << "reply: ";
                  printByHexData(packet, hdr->len);
                  break;
              case 0:
                  cout<<"need a sec.. to packet capture"<<endl;
                  continue;
              case -1:
                  perror("pcap_next_ex function has an error!!!");
                  exit(1);
              case -2:
                  cout<<"the packet have reached EOF!!"<<endl;
                  exit(0);
              default:
                  break;
          }
      }

    return 0;
}
