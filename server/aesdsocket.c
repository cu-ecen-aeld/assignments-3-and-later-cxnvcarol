#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <netdb.h> // For getaddrinfo()
#include <pthread.h>
#include "socket_thread.h"

#define PORT "9000" // Use string for getaddrinfo()
#define FILE_PATH "/var/tmp/aesdsocketdata"

SLIST_HEAD(slisthead, slist_data_s)
head;
slist_socket_t *datap;

int sockfd = -1;
int file_fd = -1;
bool should_stop = false;
pthread_mutex_t data_mutex;

void handle_signals(int signal)
{
    // Log the signal caught
    syslog(LOG_INFO, "Caught signal %d, exiting", signal);
    should_stop = true;
}

void cleanup_and_exit()
{
    syslog(LOG_INFO, "Cleaning up");

    // Close file descriptor if open
    if (file_fd != -1)
    {
        close(file_fd);
    }
    while (!SLIST_EMPTY(&head))
    {
        syslog(LOG_DEBUG, "Cleaning thread..");
        datap = SLIST_FIRST(&head);
        pthread_join(datap->value->sthread, NULL);

        if (datap->value->client_sockfd != -1)
        {
            close(datap->value->client_sockfd);
        }
        free(datap->value->buffer);
        datap->value->buffer = NULL;
        free(datap->value);
        datap->value = NULL;
        SLIST_REMOVE_HEAD(&head, entries);
        free(datap);
    }

    syslog(LOG_DEBUG, "All threads cleaned");

    // Close the server socket
    if (sockfd != -1)
    {
        close(sockfd);
    }

    // Delete file
    remove(FILE_PATH);

    closelog();
    exit(0);
}

void *client_thread_func(void *params)
{
    socket_thread_t *mysocketstruct = (socket_thread_t *)params;
    ssize_t receivedsize;

    // Step 7: Log client IP address
    syslog(LOG_INFO, "Accepted connection from %s", mysocketstruct->ip_address_str);

    // Step 9: Receive data and process packets separated by newlines
    ssize_t total_size = 0;

    while ((receivedsize = recv(mysocketstruct->client_sockfd, mysocketstruct->buffer, BUFFER_SIZE, 0)) > 0)
    {
        syslog(LOG_DEBUG, "receied %ld bytes", receivedsize);
        char *pos_newline = mysocketstruct->buffer[BUFFER_SIZE - 1] != '\0' ? NULL : strchr(mysocketstruct->buffer, '\n');
        ssize_t size_to_save = 0;
        if (!pos_newline)
        {
            // increase buffer size
            size_to_save = BUFFER_SIZE;
            syslog(LOG_DEBUG, "no break found\n");
        }
        else
        {
            size_to_save = pos_newline - mysocketstruct->buffer + 1; // 1 including the position of the breakline
        }
        total_size += size_to_save;
        pthread_mutex_lock(&data_mutex);

        if (write(file_fd, mysocketstruct->buffer, size_to_save) == -1)
        {
            syslog(LOG_ERR, "File write failed: %s", strerror(errno));
            // free(mysocketstruct->buffer);
            break;
        }
        if (pos_newline)
        {
            memset(mysocketstruct->buffer, 0, BUFFER_SIZE); // used now for reading.

            // Send the entire file content back to the client
            if (lseek(file_fd, 0, SEEK_SET) == -1) // Reset the file pointer to the beginning
            {
                perror("failed resetting file cursor.");
                exit(-1);
            }

            ssize_t read_size;
            while ((read_size = read(file_fd, mysocketstruct->buffer, BUFFER_SIZE)) > 0)
            {
                syslog(LOG_DEBUG, "sending back %ld chars'\n", read_size);
                send(mysocketstruct->client_sockfd, mysocketstruct->buffer, read_size, 0);
                memset(mysocketstruct->buffer, 0, BUFFER_SIZE);
            }
            syslog(LOG_DEBUG, "Sent all back.");
            close(mysocketstruct->client_sockfd);
            syslog(LOG_INFO, "Closed connection from %s", mysocketstruct->ip_address_str);
            mysocketstruct->completed = true;
            pthread_mutex_unlock(&data_mutex);
            break;
        }
        else
        {
            memset(mysocketstruct->buffer, 0, BUFFER_SIZE);
            syslog(LOG_DEBUG, "reset buffer for larger packet");

            pthread_mutex_unlock(&data_mutex);
        }
    }

    if (receivedsize == -1)
    {
        syslog(LOG_ERR, "Receive failed: %s", strerror(errno));
    }
    return params;
}
void log_timestamp(int sig, siginfo_t *si, void *uc)
{
    time_t now;
    char buffer[64] = {0};

    time(&now);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %T %z", tm_info);

    pthread_mutex_lock(&data_mutex);
    syslog(LOG_DEBUG, "Timestamp: %s", buffer);
    if (write(file_fd, "timestamp:", 10) == -1)
    {
        perror("Failed writing timestamp");
    }
    if (write(file_fd, buffer, sizeof(buffer)) == -1)
    {
        perror("Failed writing timestamp");
    }
    if (write(file_fd, "\n", 1) == -1)
    {
        perror("Failed writing timestamp");
    }
    pthread_mutex_unlock(&data_mutex);
}
void setup_timer()
{

    struct sigaction satimer;
    struct sigevent sev;
    struct itimerspec its;
    timer_t timerid;

    // Set up signal handler
    satimer.sa_flags = SA_SIGINFO;
    satimer.sa_sigaction = log_timestamp;
    sigemptyset(&satimer.sa_mask);
    if (sigaction(SIGRTMIN, &satimer, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // Set up the timer event to send SIGRTMIN
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_ptr = &timerid;

    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1)
    {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    // Set the timer to fire every 10 seconds
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timerid, 0, &its, NULL) == -1)
    {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }
}
int main(int argc, char const *argv[])
{
    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);
    bool demonize = false;

    if (argc > 1 && strcmp(argv[1], "-d") == 0)
    {
        syslog(LOG_DEBUG, "Should run as daemon");
        demonize = true;
    }

    SLIST_INIT(&head);

    struct addrinfo hints, *res;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_mutex_init(&data_mutex, NULL);

    // Register signal handlers for graceful exit
    struct sigaction sa;
    sa.sa_handler = handle_signals;
    sa.sa_flags = 0; // No SA_RESTART, so accept() returns on signal
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    syslog(LOG_INFO, "Timer started, logging every 10 seconds.");

    // Step 1: Set up hints for getaddrinfo()
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // Use IPv4
    hints.ai_socktype = SOCK_STREAM; // Use stream sockets (TCP)
    hints.ai_flags = AI_PASSIVE;     // For binding to all interfaces

    // Step 2: Get address info
    int status = getaddrinfo(NULL, PORT, &hints, &res);
    if (status != 0)
    {
        syslog(LOG_ERR, "getaddrinfo failed: %s", gai_strerror(status));
        return -1;
    }

    // Step 3: Create socket
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1)
    {
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }
    // From https://beej.us/guide/bgnet/html/#getaddrinfoprepare-to-launch
    // lose the pesky "Address already in use" error message.
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1)
    {
        perror("setsockopt");
        exit(1);
    }

    // Step 4: Bind socket to address
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1)
    {
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }
    if (demonize)
    {
        pid_t pid = fork();
        if (pid > 0)
        {
            // parentprocess
            exit(0);
        }

        // child process continue
        if (setsid() < 0)
        {
            perror("Failed to detach terminal session");
            exit(EXIT_FAILURE);
        }
    }

    // Step 5: Listen for a connection
    if (listen(sockfd, 1) == -1)
    {
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }

    syslog(LOG_INFO, "Server is listening on port %s", PORT);

    // Free the address info as it's no longer needed
    freeaddrinfo(res);

    // Step: Open file for appending data
    file_fd = open(FILE_PATH, O_RDWR | O_CREAT | O_APPEND, 0666); // rw-rw-rw-
    if (file_fd == -1)
    {
        perror("File open failed");
        exit(0);
    }
    syslog(LOG_DEBUG, "opened file ok");

    setup_timer();

    while (!should_stop)
    {
        // Step 6: Accept client connection
        int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd == -1)
        {
            syslog(LOG_DEBUG, "Accept client skipped: %s", strerror(errno));
            continue; // Continue to the next connection attempt
        }
        socket_thread_t *item;
        item = init_socket();
        item->client_sockfd = client_sockfd;
        item->ip_address_str = inet_ntoa(client_addr.sin_addr);

        // 1. create thread and add to list

        if (pthread_create(&item->sthread, NULL, client_thread_func, item) != 0)
        {
            perror("pthread_create failed");
            return 1;
        }

        datap = malloc(sizeof(slist_socket_t));
        datap->value = item;
        SLIST_INSERT_HEAD(&head, datap, entries);

        // 2. iterate over list and join if completed. // TODO

        SLIST_FOREACH(datap, &head, entries)
        {
            if (datap->value->completed)
            {
                syslog(LOG_DEBUG, "completed normally, joining...");
                pthread_join(datap->value->sthread, NULL);
            }
        }
    }
    cleanup_and_exit();
    return 0;
}
