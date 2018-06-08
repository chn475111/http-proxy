#ifndef __FILE_UTILS_H__
#define __FILE_UTILS_H__

#include <stdbool.h>

int file_mmap(char *filename, char **file, int *filesize);

void file_munmap(char *file, int filesize);

bool is_dir_exist(const char *pathname);

bool is_file_exist(const char *filename);

#endif
