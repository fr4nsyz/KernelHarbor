#ifndef __OPEN_H__
#define __OPEN_H__

// access modes (mutually exclusive)
#define O_RDONLY    00
#define O_WRONLY    01
#define O_RDWR      02

// file creation flags
#define O_CREAT     0100
#define O_EXCL      0200
#define O_NOCTTY    0400
#define O_TRUNC     01000

// file status flags
#define O_APPEND    02000
#define O_NONBLOCK  04000
#define O_DSYNC     010000
#define O_SYNC      04010000
#define O_ASYNC     020000
#define O_DIRECT    040000
#define O_LARGEFILE 0100000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW  0400000
#define O_NOATIME   01000000
#define O_CLOEXEC   02000000
#define O_PATH      010000000
#define O_TMPFILE   020200000

// file mode bits (permissions)
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000

#define S_IRWXU 0700
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100

#define S_IRWXG 070
#define S_IRGRP 040
#define S_IWGRP 020
#define S_IXGRP 010

#define S_IRWXO 07
#define S_IROTH 04
#define S_IWOTH 02
#define S_IXOTH 01

#endif
