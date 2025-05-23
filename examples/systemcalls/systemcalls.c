#include "systemcalls.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * DONE  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    int result=system(cmd);
    if(result==-1)
    {
        return false;
    }
    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

/*
 * Done.
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command. 
 * 
 *  HINT for the @authors:: this was not a good instruction:: as second argument all arguments should be used for execv, not the remaining ones.
 *
*/
    printf("Exec called %s with %d args\n", command[0],count);
    fflush(stdout); // @authors Now, that was a good hint in the exercise instructions. Why not as comment here?
    bool success=true;
    pid_t pid= fork ();    

    if(pid==0){
        // child process
        execv(command[0], &command[0]);
        // if it continues it was an error, otherwise the execv process takes over.
        perror("Error with execv");
        exit(EXIT_FAILURE);
    }
    int status;
        
    waitpid(pid, &status, 0);
    printf("status %d\n", status);

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        printf("Exit code: %d\n", exit_code);
        if(exit_code!=0){
            success=false;
        }
    }

    va_end(args);

    return success;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];


/*
 * Done.
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
 *  HINT for the @authors: without implementing this function yet, the first part of the test_exec_redirect_calls was already passing.
 *  The reason being that the REDIRECT_FILE is also used in test_systemcalls and is never cleaned up!!
*/


    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0) { perror("open"); abort(); }
    
    // as in previous exec:
    bool success=true;
    pid_t pid= fork ();

    if(pid==0){
        // child process
        if (dup2(fd, 1) < 0) { perror("dup2"); abort(); }
        close(fd);

        execv(command[0], &command[0]);
        // if it continues it was an error, otherwise the execv process takes over.
        perror("Error with execv");
        exit(EXIT_FAILURE);
    }
    int status;
        
    waitpid(pid, &status, 0);
    printf("status %d\n", status);

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        printf("Exit code: %d\n", exit_code);
        if(exit_code!=0){
            success=false;
        }
    }
    close(fd);


    va_end(args);

    return success;
}
