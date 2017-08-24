#ifndef __FILE_UTILS_H__
#define __FILE_UTILS_H__

#include <stdbool.h>

int file_mmap(char *filename, char **file, int *filesize);

void file_munmap(char *file, int filesize);

int read_file(const char *filename, char *mode, char *output, int output_len);

int write_file(const char *filename, char *mode, char *input, int input_len);

bool is_file_exist(const char *filename);

bool is_dir_exist(const char *filename);

#endif
