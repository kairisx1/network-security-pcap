# PCAP Programming 과제

C 기반 PCAP API를 사용하여 TCP 패킷의 주요 정보를 출력하는 프로그램을 구현한 과제입니다.

---

## 구현 파일

- 'sniff_improved.c'  
  ➤ **Ethernet / IP / TCP 헤더** 정보 및 최대 30바이트의 **Payload**를 출력하도록 구현  
  ➤ 'sniff.c', 'udp_server.c' 등은 제외하고 과제에 해당하는 핵심 코드만 남김

---

## 실행 방법

### 1. 컴파일

gcc sniff_improved.c -o tcp_sniff -lpcap

### 2. 실행

sudo ./tcp_sniff
