#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

char dest_addr[1024] = {0};

unsigned short in_cksum(unsigned short* addr, int length)
{
    int nleft = length;
    unsigned short* w = addr;
    unsigned short answer;
    int sum = 0;
    while (nleft > 0) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        sum += htons((*w) << 8);
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    answer = ~sum;
    return answer;
}

void check_receive_msg(char* msg)
{
    struct iphdr* ip = (struct iphdr*)msg;
    struct icmphdr* icmp = (struct icmphdr*)(msg + sizeof(struct iphdr));
    struct sockaddr_in tmp;
    tmp.sin_addr.s_addr = ip->saddr;
    printf("source ip is %s\n", inet_ntoa(tmp.sin_addr));
    unsigned short ip_cksum = in_cksum((unsigned short*)ip, sizeof(struct iphdr));
    unsigned short icmp_cksum = in_cksum((unsigned short*)icmp, sizeof(struct icmphdr) + sizeof(struct timeval));
    printf("ip_cksum = %d, icmp_cksum = %d\n", ip_cksum, icmp_cksum);
}

void get_addr(struct sockaddr_in* dest, struct sockaddr_in* source)
{
    struct sockaddr_in _dest;
    struct hostent* host;
    int probe_fd;
    socklen_t len;
    host = gethostbyname(dest_addr);
    if (host == NULL) {
        printf("error addr!\n");
        exit(1);
    }
    snprintf(dest_addr, sizeof(dest_addr), "%d.%d.%d.%d", host->h_addr_list[0][0] & 0xFF, host->h_addr_list[0][1] & 0xFF, host->h_addr_list[0][2] & 0xFF, host->h_addr_list[0][3] & 0xFF);
    dest->sin_family = AF_INET;
    inet_aton(dest_addr, &(dest->sin_addr));
    _dest = *dest;
    probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_fd < 0) {
        printf("creat probe_fd fail, error = %d, %s\n", errno, strerror(errno));
        exit(1);
    }
    if (connect(probe_fd, (struct sockaddr*)&_dest, sizeof(_dest)) == -1) {
        printf("connect fail, error = %d, %s\n", errno, strerror(errno));
        close(probe_fd);
        exit(1);
    }
    len = sizeof(struct sockaddr_in);
    if (getsockname(probe_fd, (struct sockaddr*)source, &len) == -1) {
        printf("getsockname fail, error = %d, %s\n", errno, strerror(errno));
        close(probe_fd);
        exit(1);
    }
    close(probe_fd);

    printf("dest addr = %s\n", inet_ntoa(dest->sin_addr));
    printf("source addr = %s\n", inet_ntoa(source->sin_addr));
}

int main(int argc, char** argv)
{
    struct sockaddr_in dest;
    struct sockaddr_in source;
    char* pack;
    struct iphdr* ip;
    struct icmphdr* icmp;
    struct timeval* time_data;
    int pack_len;
    char buf[65535];
    int rc;
    int optval = 1;
    int my_pid = htons(getpid() & 0xFFFF);

    if (argc != 2) {
        printf("error paramenter!\n");
        exit(1);
    }
    strncpy(dest_addr, argv[1], strlen(argv[1]));

    /* get source addr and dest addr */
    get_addr(&dest, &source);

    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        printf("creat socket fail, error = %d, %s\n", errno, strerror(errno));
        exit(1);
    }

    if (setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0) {
        printf("setsockopt fail\n");
        close(icmp_sock);
        exit(1);
    }

    /* make packet */
    pack_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval);
    pack = malloc(pack_len);
    ip = (struct iphdr*)pack;
    icmp = (struct icmphdr*)(pack + sizeof(struct iphdr));
    time_data = (struct timeval*)(pack + sizeof(struct iphdr) + sizeof(struct icmphdr));

    ip->ihl = 5;
    ip->tot_len = htons(pack_len);
    ip->version = 4;
    ip->tos = 0;
    ip->id = htons(random());
    ip->frag_off = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = source.sin_addr.s_addr;
    ip->daddr = dest.sin_addr.s_addr;
    ip->check = in_cksum((unsigned short*)ip, sizeof(struct iphdr));

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = my_pid;
    icmp->un.echo.sequence = 1;

    gettimeofday(time_data, NULL);

    icmp->checksum = in_cksum((unsigned short*)icmp, sizeof(struct icmphdr) + sizeof(struct timeval));

    rc = sendto(icmp_sock, pack, pack_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (rc == -1) {
        printf("send pack fail, error = %d, %s\n", errno, strerror(errno));
        close(icmp_sock);
        exit(1);
    }
    struct pollfd icmp_poll;
    icmp_poll.fd = icmp_sock;
    icmp_poll.events = POLLIN | POLLERR;
    icmp_poll.revents = 0;
    rc = poll(&icmp_poll, 1, 1000);
    if (rc < 1 || !(icmp_poll.revents & (POLLIN | POLLERR))) {
        printf("poll fail\n");
        close(icmp_sock);
        exit(1);
    }
    rc = recv(icmp_sock, buf, 65535, 0);
    if (rc < 0) {
        printf("receive msg fail, error = %d, %s\n", errno, strerror(errno));
        close(icmp_sock);
        exit(1);
    }
    else {
        check_receive_msg(buf);
        close(icmp_sock);
        exit(0);
    }
    return 0;
}
