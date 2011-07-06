/*
* Azzurra IRC Services
* 
* datafiles.c - database files handling routines
* 
* Basato su:
*   SirvNET Services is copyright (c) 1998-2001 Trevor Klingbeil. (E-mail: <priority1@dal.net>)
*   Originally based on EsperNet Services(c) by Andy Church.
* 
* Versione : LANG_VERS_A1 (1)
* 
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#include "data.h"

#define MAX_PATH	260


/*************************************************************************/

/* Return the version number on the file. Panic if there is no version
* number or the number doesn't make sense (i.e. less than 1 or greater
* than FILE_VERSION).
*/

int get_file_version(FILE *f, const char *filename) {

	int version = fgetc(f)<<24 | fgetc(f)<<16 | fgetc(f)<<8 | fgetc(f);

	if (ferror(f))
		fatal("Error reading version number on %s", filename);

	else if (version > FILE_VERSION || version < 1)
		fatal("Invalid version number (%d) on %s", version, filename);

	return version;
}

/*************************************************************************/

/* Write the current version number to the file. Return 0 on error, 1 on success. */

int write_file_version(FILE *f, const char *filename) {

	if (fputc(FILE_VERSION>>24 & 0xFF, f) < 0 || fputc(FILE_VERSION>>16 & 0xFF, f) < 0 ||
		fputc(FILE_VERSION>> 8 & 0xFF, f) < 0 || fputc(FILE_VERSION & 0xFF, f) < 0) {

		fatal("Error writing version number on %s", filename);
		return 0;
	}

	return 1;
}

/*************************************************************************/

static FILE *open_db_read(const char *service, const char *filename) {

	FILE *f = fopen(filename, "r");

	if (!f) {

		if (errno != ENOENT)
			fatal("Can't read %s database %s", service, filename);

		return NULL;
	}

	return f;
}

/*************************************************************************/

static FILE *open_db_write(const char *service, const char *filename) {

	char namebuf[MAX_PATH + 1];
	FILE *f;

	memset(namebuf, 0, MAX_PATH + 1);
	snprintf(namebuf, sizeof(namebuf), "%s.save", filename);

	if (!*namebuf || (strcmp(namebuf, filename) == 0)) {

		errno = ENAMETOOLONG;
		fatal("Can't back up %s database %s", service, filename);
		return NULL;
	}
	unlink(namebuf);

	if (rename(filename, namebuf) < 0 && errno != ENOENT) {

		/*static unsigned int walloped = 0;

		if (!walloped) {

			walloped++;
			send_globops(NULL, "Can't back up %s database %s", service, filename);
		}*/

		fatal("Can't back up %s database %s", service, filename);

#ifndef NO_BACKUP_OKAY
		return NULL;
#endif
	}

	f = fopen(filename, "w");

	if (!f || !write_file_version(f, filename)) {

		/*static unsigned int walloped = 0;

		if (!walloped) {

			walloped++;
			send_globops(NULL, "Can't write to %s database %s", service, filename);
		}*/

		fatal("Can't write to %s database %s", service, filename);

		if (f) {

			fclose(f);
			unlink(filename);
		}

		if (rename(namebuf, filename) < 0
#ifdef NO_BACKUP_OKAY
			&& errno != ENOENT
#endif
			) {

			/* Better quit; something might be seriously wrong */
			fatal("Cannot restore backup copy of %s", filename);
		}

		return NULL;
	}

	return f;
}

/*************************************************************************/

/* Open a database file for reading (*mode == 'r') or writing (*mode == 'w').
* Return the stream pointer, or NULL on error. When opening for write, it
* is an error for rename() to return an error (when backing up the original
* file) other than ENOENT, if NO_BACKUP_OKAY is not defined; it is an error
* if the version number cannot be written to the file; and it is a fatal
* error if opening the file for write fails and the backup was successfully
* made but cannot be restored.
*/

FILE *open_db(const char *service, const char *filename, const char *mode) {
	
	if (*mode == 'r')
		return open_db_read(service, filename);

	else if (*mode == 'w')
		return open_db_write(service, filename);

	else {

		errno = EINVAL;
		return NULL;
	}
}

/*************************************************************************/

/* Close a database file. If the file was opened for write, remove the
* backup we (may have) created earlier.
*/

void close_db(FILE *dbfile, const char *filename) {

	int flags;

	flags = fcntl(fileno(dbfile), F_GETFL);

	if ((flags != -1) && (((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR))) {

		char namebuf[MAX_PATH+1];

		snprintf(namebuf, sizeof(namebuf), "%s.save", filename);

		if (*namebuf && (strcmp(namebuf, filename) != 0))
			remove(namebuf);
	}

	fclose(dbfile);
}

/*************************************************************************/

/* read_string, write_string:
 *	Read a string from a file, or write a string to a file, with the
 *	string length prefixed as a two-byte big-endian integer. The
 *	filename is passed in so that it can be reported in the log file
 *	(and possibly with globops) if an error occurs.
 */

char *read_string(FILE *f, const char *filename) {

	char *s;
	int len;

	len = fgetc(f) * 256 + fgetc(f);

	s = malloc(len);

	if (len != fread(s, 1, len, f)) {

		fprintf(stderr, "Read error on file: %s", filename);
		exit(1);
	}

	return s;
}

/*************************************************************************/

char *write_string(const char *s, FILE *f, const char *filename) {

	int i;

	i = strlen(s) + 1;		/* Include trailing null */

	fputc(i / 256, f);
	fputc(i & 255, f);

	if (i != fwrite(s, 1, i, f))
		fatal("Write error on file: %s", filename);

	return (char *)s;
}

