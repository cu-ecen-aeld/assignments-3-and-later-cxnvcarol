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
#include <stdbool.h>

#define PORT "9000" // Use string for getaddrinfo()
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024
char *buffer;

int sockfd = -1;
int file_fd = -1;
int client_sockfd = -1;
bool should_stop = false;

void handle_signals(int signal)
{
    // Log the signal caught
    syslog(LOG_INFO, "Caught signal %d, exiting", signal);
    should_stop = true;
}

void cleanup_and_exit()
{

    // Close file descriptor if open
    if (file_fd != -1)
    {
        close(file_fd);
    }

    // Close the client socket if connected
    if (client_sockfd != -1)
    {
        close(client_sockfd);
    }

    // Close the server socket
    if (sockfd != -1)
    {
        close(sockfd);
    }

    // Delete file // TODO. Uncomment next comment.
    remove(FILE_PATH);
    free(buffer);

    // Close syslog
    closelog();

    exit(0);
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

    struct addrinfo hints, *res;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // char *packet;
    // ssize_t packet_len = 0;
    ssize_t receivedsize;

    // Register signal handlers for graceful exit
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

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

    buffer = calloc(BUFFER_SIZE, 1);
    if (buffer == NULL)
    {
        perror("allocating initial memory");
        exit(0);
    }
    while (!should_stop)
    {
        // Step 6: Accept client connection
        client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd == -1)
        {
            syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
            continue; // Continue to the next connection attempt
        }

        // Step 7: Log client IP address
        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(client_addr.sin_addr));

        // Step 8: Open file for appending data // TODO. move outside the loop?
        file_fd = open(FILE_PATH, O_RDWR | O_CREAT | O_APPEND, 0666); // rw-rw-rw-
        if (file_fd == -1)
        {
            syslog(LOG_ERR, "File open failed: %s", strerror(errno));
            close(client_sockfd);
            continue; // Continue to the next connection attempt
        }
        syslog(LOG_DEBUG, "opened file ok");

        // Step 9: Receive data and process packets separated by newlines
        ssize_t total_size = 0;

        while ((receivedsize = recv(client_sockfd, buffer, BUFFER_SIZE, 0)) > 0)
        {
            char *pos_newline = buffer[BUFFER_SIZE - 1] != '\0' ? NULL : strchr(buffer, '\n');
            // char *pos_newline = strchr(buffer, '\n');
            ssize_t size_to_save = 0;
            if (!pos_newline || pos_newline == NULL)
            {
                // increase buffer size
                size_to_save = BUFFER_SIZE;
                syslog(LOG_DEBUG, "no break found\n");
            }
            else
            {
                size_to_save = pos_newline - buffer + 1; // 1 including the position of the breakline
            }
            total_size += size_to_save;

            if (write(file_fd, buffer, size_to_save) == -1)
            {
                syslog(LOG_ERR, "File write failed: %s", strerror(errno));
                free(buffer);
                break;
            }
            if (pos_newline)
            {
                // buffer = malloc(BUFFER_SIZE); // used now for reading.
                free(buffer);
                buffer = calloc(BUFFER_SIZE, 1);

                // Send the entire file content back to the client
                if (lseek(file_fd, 0, SEEK_SET) == -1) // Reset the file pointer to the beginning
                {
                    perror("failed resetting file cursor.");
                    exit(-1);
                }

                ssize_t read_size;
                while ((read_size = read(file_fd, buffer, BUFFER_SIZE)) > 0)
                {
                    syslog(LOG_DEBUG, "sending back %ld chars'\n", read_size);
                    send(client_sockfd, buffer, read_size, 0);
                    free(buffer);
                    buffer = calloc(BUFFER_SIZE, 1);
                }
                syslog(LOG_DEBUG, "Sent all back.");
                close(client_sockfd);
                syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(client_addr.sin_addr));
                break;
            }
            else
            {
                free(buffer);
                buffer = calloc(BUFFER_SIZE, 1);
                if (buffer == NULL)
                {
                    perror("While allocating extra memory");
                    exit(0);
                }
                syslog(LOG_DEBUG, "allocated extra for packet");
            }
        }

        if (receivedsize == -1)
        {
            syslog(LOG_ERR, "Receive failed: %s", strerror(errno));
        }
        else
        {
            syslog(LOG_DEBUG, "Last received is %ld", receivedsize);
        }
    }
    cleanup_and_exit();
    return 0;
}
