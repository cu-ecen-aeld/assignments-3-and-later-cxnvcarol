#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <syslog.h>
#include <stddef.h>
#include <fcntl.h>
// #include <sys/stat.h>
#include <unistd.h>
#include <string.h>

// #include <netinet/in.h>
// #include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

#define PORT 9000
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024

int sockfd = -1;
int file_fd = -1;
int client_sockfd = -1;

void cleanup_and_exit(int signal)
{
	// Log the signal caught
	syslog(LOG_INFO, "Caught signal %d, exiting", signal);

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

	// Delete the file
	unlink(FILE_PATH);

	// Close syslog
	closelog();

	exit(0);
}

int main()
{
	// struct sockaddr_in server_addr, client_addr;
	// socklen_t client_len = sizeof(client_addr);
	char buffer[BUFFER_SIZE];
	char *packet;
	size_t packet_len = 0;
	ssize_t n;
	FILE *file;
	// struct stat file_stat;

	// Open syslog
	openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);

	// Register signal handlers for graceful exit
	signal(SIGINT, cleanup_and_exit);
	signal(SIGTERM, cleanup_and_exit);

	// Step 1: Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
		return -1;
	}

	// Step 2: Set server address. # TODO. instead use readaddr.
	// memset(&server_addr, 0, sizeof(server_addr));
	// server_addr.sin_family = AF_INET;
	// server_addr.sin_addr.s_addr = INADDR_ANY;
	// server_addr.sin_port = htons(PORT);

	// Step 3: Bind socket
	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
	{
		syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	// Step 4: Listen for incoming connections
	if (listen(sockfd, 5) == -1)
	{
		syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	syslog(LOG_INFO, "Server is listening on port %d", PORT);

	while (1)
	{
		// Step 5: Accept client connection
		client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
		if (client_sockfd == -1)
		{
			syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
			continue; // Continue to the next connection attempt
		}

		// Step 6: Log client IP address
		syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(client_addr.sin_addr));

		// Step 7: Open file for appending data
		file_fd = open(FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (file_fd == -1)
		{
			syslog(LOG_ERR, "File open failed: %s", strerror(errno));
			close(client_sockfd);
			continue; // Continue to the next connection attempt
		}

		// Step 8: Receive data and process packets separated by newlines
		while ((n = recv(client_sockfd, buffer, sizeof(buffer), 0)) > 0)
		{
			size_t i;
			for (i = 0; i < n; i++)
			{
				// If newline is found, process the packet
				if (buffer[i] == '\n')
				{
					packet = malloc(packet_len + 1);
					if (!packet)
					{
						syslog(LOG_ERR, "Memory allocation failed");
						packet_len = 0; // Reset and discard current packet
						continue;
					}

					// Copy the received packet to the newly allocated buffer
					memcpy(packet, buffer, packet_len);
					packet[packet_len] = '\0'; // Null-terminate the string

					// Append packet to file
					if (write(file_fd, packet, packet_len) == -1)
					{
						syslog(LOG_ERR, "File write failed: %s", strerror(errno));
						free(packet);
						break;
					}

					// Append the newline character to the file as well
					if (write(file_fd, "\n", 1) == -1)
					{
						syslog(LOG_ERR, "File write failed for newline: %s", strerror(errno));
						free(packet);
						break;
					}

					// Send the entire file content back to the client
					lseek(file_fd, 0, SEEK_SET); // Reset the file pointer to the beginning
					file = fopen(FILE_PATH, "r");
					if (file)
					{
						while (fgets(buffer, sizeof(buffer), file) != NULL)
						{
							send(client_sockfd, buffer, strlen(buffer), 0);
						}
						fclose(file);
					}

					free(packet);	// Free allocated memory for the packet
					packet_len = 0; // Reset packet length for next packet
				}
				else
				{
					// Accumulate data in the buffer for the current packet
					if (packet_len < BUFFER_SIZE - 1)
					{
						buffer[packet_len++] = buffer[i];
					}
					else
					{
						// If the packet is too long, discard it and reset
						syslog(LOG_ERR, "Received packet too large, discarding it");
						packet_len = 0;
					}
				}
			}
		}

		if (n == -1)
		{
			syslog(LOG_ERR, "Receive failed: %s", strerror(errno));
		}

		// Log the client disconnection
		syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(client_addr.sin_addr));

		// Close file and client socket
		close(file_fd);
		close(client_sockfd);
	}

	// Cleanup and exit (should never be reached due to the loop)
	cleanup_and_exit(0);
	return 0;
}
