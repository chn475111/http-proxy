#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "log.h"
#include "file_utils.h"

int file_mmap(char *filename, char **file, int *filesize)
{
    int rv = -1;
    int fd = -1;
    struct stat st;

    rv = stat(filename, &st);
    if(rv == -1)
    {
        log_err("stat failed - %d: %s", errno, strerror(errno));
        return -1;
    }
    *filesize = st.st_size;

    fd = open(filename, O_RDONLY);
    if(fd == -1)
    {
        log_err("open failed - %d: %s", errno, strerror(errno));
        return -1;
    }

    *file = (char*)mmap(NULL, *filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if(*file == MAP_FAILED)
    {
        log_err("mmap failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }

    if(fd > 0) close(fd);
    return 0;
ErrP:
    if(fd > 0) close(fd);
    return -1;
}

void file_munmap(char *file, int filesize)
{
    munmap(file, filesize);
}

int read_file(const char *filename, char *mode, char *output, int output_len)
{
    int ch = 0;
    int count = 0;
    FILE *fp = NULL;

    if(!filename || !mode || !output || output_len <= 0)
        return -1;

    fp = fopen(filename, mode);
    if(fp == NULL)
    {
        log_err("fopen failed - %d: %s", errno, strerror(errno));
        return -1;
    }

    while((ch = fgetc(fp)) != EOF)
    {
        if(count >= output_len-1)
            break;
        output[count++] = ch;
    }
    output[count] = 0;

    if(fp) fclose(fp);
    return count;
}

int write_file(const char *filename, char *mode, char *input, int input_len)
{
    int ret = 0;
    FILE *fp = NULL;

    if(!filename || !mode || !input || input_len < 0)
        return -1;

    fp = fopen(filename, mode);
    if(fp == NULL)
    {
        log_err("fopen failed - %d: %s", errno, strerror(errno));
        return -1;
    }

    ret = fwrite(input, 1, input_len, fp);
    if(ret != input_len)
    {
        log_err("fwrite failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }

    if(fp) fclose(fp);
    return ret;
ErrP:
    if(fp) fclose(fp);
    return -1;
}

bool is_file_exist(const char *filename)
{
    if(filename == NULL)
        return false;

    return access(filename, F_OK) == 0;
}

bool is_dir_exist(const char *filename)
{
    if(filename == NULL)
        return false;

    return opendir(filename) != NULL;
}
