/*
 * test-dirfd: exercise the openat() syscall with dirfd != AT_FDCWD.
 *
 * Opens one or more directories by path, then periodically calls openat()
 * with those directory file descriptors so the BPF openat-tracer can
 * verify its dentry-walk path resolution.
 *
 * Usage: ./test-dirfd [interval_ms]
 *   interval_ms  – milliseconds between openat() calls (default 2000)
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct dir_entry {
	const char *path;
	int fd;
};

static struct dir_entry dirs[] = {
	{ "/tmp",           -1 },
	{ "/var/log",       -1 },
	{ "/etc",           -1 },
	{ "/usr/share",     -1 },
};

#define N_DIRS (sizeof(dirs) / sizeof(dirs[0]))

static void msleep(unsigned ms)
{
	struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
}

int main(int argc, char *argv[])
{
	setbuf(stdout, NULL);  /* disable buffering so output appears immediately */

	unsigned interval_ms = 2000;
	if (argc > 1)
		interval_ms = (unsigned)atoi(argv[1]);

	/* Open each directory to get a non-AT_FDCWD fd. */
	int opened = 0;
	for (size_t i = 0; i < N_DIRS; i++) {
		dirs[i].fd = open(dirs[i].path, O_RDONLY | O_DIRECTORY);
		if (dirs[i].fd < 0) {
			fprintf(stderr, "warning: open(%s): %s\n", dirs[i].path, strerror(errno));
			continue;
		}
		printf("opened %s  ->  fd %d\n", dirs[i].path, dirs[i].fd);
		opened++;
	}

	if (opened == 0) {
		fprintf(stderr, "error: could not open any directories\n");
		return 1;
	}

	printf("\n--- calling openat() every %u ms (Ctrl+C to stop) ---\n\n", interval_ms);

	unsigned round = 0;
	for (;;) {
		round++;
		for (size_t i = 0; i < N_DIRS; i++) {
			if (dirs[i].fd < 0)
				continue;

			/*
			 * Try to open a file relative to dirfd.
			 * The file doesn't need to exist — the openat() syscall
			 * is still issued (and traced) before the kernel returns
			 * -ENOENT.  We also try a real path ("." always exists).
			 */
			const char *targets[] = {
				".",                       /* always exists */
				"test-dirfd-probe.tmp",   /* likely does not exist */
			};

			for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
				int fd = openat(dirs[i].fd, targets[t], O_RDONLY);
				printf("[round %u] openat(fd=%d [%s], \"%s\") = %d%s\n",
					round, dirs[i].fd, dirs[i].path, targets[t],
					fd, (fd < 0 ? "  (expected)" : ""));
				if (fd >= 0)
					close(fd);
			}
		}

		printf("\n");
		msleep(interval_ms);
	}

	/* unreachable, but tidy */
	for (size_t i = 0; i < N_DIRS; i++)
		if (dirs[i].fd >= 0)
			close(dirs[i].fd);

	return 0;
}
