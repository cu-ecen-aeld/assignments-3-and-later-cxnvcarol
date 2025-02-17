#include <syslog.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>


int main(int argc, char const *argv[])
{
    openlog(NULL,0,LOG_USER);

    syslog(LOG_INFO,"Writer with %d arguments.\n", argc);
    
    
    if(argc!=3){ //hint: first argument is the program name (like in shell)
        syslog(LOG_ERR,"Expected number of arguments is 3 (including program name), but it was: %d\n", argc);
        return -1;
    }

    const char* writefile=argv[1];
    const char* writestr=argv[2];
    syslog(LOG_DEBUG,"“Writing %s to %s” ", writestr, writefile);

    int fd=open(writefile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

    if (fd == -1){
        syslog(LOG_ERR,"Unexpected error opening file %s",writefile);
        return -1;
    }

    ssize_t nr=write (fd, writestr, strlen (writestr));
    write(fd, "\n", 1); //EOL seemed necessary for the finder-test :whatever:

    if (nr == -1){
        syslog(LOG_ERR,"Unexpected error writing to file");
        return -1;
    }
    if (close (fd) == -1 ){
        syslog(LOG_ERR,"Unexpected error closing file");
        return -1;
    }
    syslog(LOG_INFO,"Wrote file successfully :) \n");



    return 0;
}

