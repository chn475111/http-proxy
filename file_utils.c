#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "file_utils.h"

int file_mmap(char *filename, char **file, int *filesize)
{
    int rv = -1;
    int fd = -1;
    struct stat st;

    rv = stat(filename, &st);
    if(rv == -1)
    {
        fprintf(stderr, "%s %s:%u - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }
    *filesize = st.st_size;

    fd = open(filename, O_RDONLY);
    if(fd == -1)
    {
        fprintf(stderr, "%s %s:%u - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }

    *file = (char*)mmap(NULL, *filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if(*file == MAP_FAILED)
    {
        fprintf(stderr, "%s %s:%u - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
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

bool is_dir_exist(const char *pathname)
{
    if(pathname == NULL)
        return false;

    DIR *dp = opendir(pathname);
    if(dp != NULL)
    {
        closedir(dp);
        return true;
    }
    return false;
}

bool is_file_exist(const char *filename)
{
    if(filename == NULL)
        return false;

    FILE *fp = fopen(filename, "rb");
    if(fp != NULL)
    {
        fclose(fp);
        return true;
    }
    return false;
}
