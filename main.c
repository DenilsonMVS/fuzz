#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

int fuzz_target(const uint8_t *data, size_t size) {
    char filename[] = "image";
    char eog[] = "eog";
    
    // Open the file for writing
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("Failed to open file");
        return -1;
    }

    // Write the data to the file
    ssize_t bytes_written = write(fd, data, size);
    if (bytes_written == -1) {
        perror("Failed to write to file");
        close(fd);
        return -1;
    }

    // Close the file after writing
    close(fd);

    // Fork a new process
    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        return -1;
    }

    if (pid == 0) {
        // Child process: execute 'eog' with the image file as argument
        char * argv[] = {eog, filename, NULL};
        execvp(argv[0], argv);

        // If exec fails
        perror("Exec failed");
        return -1;
    } else {
        // Parent process: wait for the child process to exit
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("Waitpid failed");
            return -1;
        }

        // Check if the child process exited successfully
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("eog exited successfully\n");
        } else {
            printf("eog failed with status %d\n", WEXITSTATUS(status));
        }
    }

    return 0;
}

int main() {
    fuzz_target(NULL, 0);
    return 0;
}

// int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
//     return fuzz_target(data, size);
// }

