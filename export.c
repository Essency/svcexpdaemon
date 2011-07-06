/*
*
* Azzurra IRC Services - Export tools
* 
* data.h
* 
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#if defined( __FreeBSD__ ) || defined( __OpenBSD__ )
#include <pwd.h>
#else
#include <crypt.h>
#endif

#include "data.h"
#include "crypt_shs1.h"
#include <limits.h>


#define AddFlag(v, f)       ((v) |= (f))
#define RemoveFlag(v, f)    ((v) &= ~(f))
#define FlagSet(v, f)       (((v) & (f)) != 0)
#define FlagUnset(v, f)     (((v) & (f)) == 0)




/* We've hit something we can't recover from. Let people know what happened, then go down. */
void fatal(const char *fmt,...) {
	
	va_list args;
	time_t t;
	struct tm tm;
	char buf[256], buf2[4096];

	va_start(args, fmt);
	time(&t);
	tm = *localtime(&t);
	strftime(buf, sizeof(buf)-1, "[%b %d %Y - %H:%M:%S (%Z)]", &tm);
	vsnprintf(buf2, sizeof(buf2), fmt, args);

	fprintf(stderr, "%s FATAL: %s\n", buf, buf2);

	exit(1);
}


void dbg_assert(const char *file, int line) {

	fprintf(stderr, "Assertion failed at %s:%d.\n", file, line);
	abort();
}

#define DBG_ASSERT(cond)	if (!(cond)) dbg_assert(__FILE__, __LINE__);


static const char	base64_digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char	base64_pad = '=';

#ifndef byte
typedef	unsigned char	byte;
#endif 

size_t base64_encode(byte const *originalData, size_t dataSize, char *buffer, size_t bufferSize) {

	size_t	datalength = 0;
	byte	input[3];
	byte	output[4];
	size_t	i;

	while (2 < dataSize) {
		input[0] = *originalData++;
		input[1] = *originalData++;
		input[2] = *originalData++;
		dataSize -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;
		DBG_ASSERT(output[0] < 64);
		DBG_ASSERT(output[1] < 64);
		DBG_ASSERT(output[2] < 64);
		DBG_ASSERT(output[3] < 64);

		if (datalength + 4 > bufferSize)
			return (-1);
		buffer[datalength++] = base64_digits[output[0]];
		buffer[datalength++] = base64_digits[output[1]];
		buffer[datalength++] = base64_digits[output[2]];
		buffer[datalength++] = base64_digits[output[3]];
	}
    
	/* Now we worry about padding. */
	if (0 != dataSize) {
		/* Get what's left. */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < dataSize; i++)
			input[i] = *originalData++;
	
		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		DBG_ASSERT(output[0] < 64);
		DBG_ASSERT(output[1] < 64);
		DBG_ASSERT(output[2] < 64);

		if (datalength + 4 > bufferSize)
			return (-1);
		buffer[datalength++] = base64_digits[output[0]];
		buffer[datalength++] = base64_digits[output[1]];
		if (dataSize == 1)
			buffer[datalength++] = base64_pad;
		else
			buffer[datalength++] = base64_digits[output[2]];
		buffer[datalength++] = base64_pad;
	}
	if (datalength >= bufferSize)
		return (-1);
	buffer[datalength] = '\0';	/* Returned value doesn't count \0. */
	return (datalength);
}


static int	rnd_fd = -1;

int rnd_init() {
    return (rnd_fd = open("/dev/urandom",O_RDONLY)) != -1;
}

void rnd_done() {
    close(rnd_fd);
}

int rnd_getblock(byte *output, unsigned int size) {
    return read(rnd_fd, output, size) == size;
}



#define CRYPTED_PASS_LENGTH	64

int CryptPassword(const char *pw, char *buffer, size_t bufferSize) {

	#define SALT_LENGTH	24

	byte	saltBytes[16];
	char	saltString[SALT_LENGTH + 1];


	if (bufferSize <= CRYPT_SHA1_DIGEST_LEN + SALT_LENGTH) { // CRYPTED_PASS_LENGTH
		//printf("invalid bufferSize\n");
		return 0;

	}

	if (rnd_getblock(saltBytes, sizeof(saltBytes))) {

		/*
		printf("saltBytes: ");
		for (int i = 0; i < 16; ++i)
			printf("%d ", saltBytes[i]);
		printf("\n");
		*/

		if (base64_encode(saltBytes, sizeof(saltBytes), saltString, sizeof(saltString)) == SALT_LENGTH) {

			//printf("saltString: %s\n", saltString);


			size_t	pwLength = strlen(pw);
			size_t	saltedPasswordLength = pwLength + SALT_LENGTH;
			char	*saltedPassword = (char*)malloc(saltedPasswordLength + 1);

			if (saltedPassword) {

				SHS1_INFO	digest;

				memcpy(saltedPassword, pw, pwLength);
				memcpy(saltedPassword + pwLength, saltString, SALT_LENGTH);
				saltedPassword[saltedPasswordLength] = 0;

				//printf("saltedPassword: %s\n", saltedPassword);

				shs1Init(&digest);
				shs1Update(&digest, (BYTE *)saltedPassword, saltedPasswordLength);
				SHS1COUNT(&digest, saltedPasswordLength);
				shs1Final(&digest);

				snprintf(buffer, bufferSize, "%08lx%08lx%08lx%08lx%08lx", digest.digest[0], digest.digest[1], digest.digest[2], digest.digest[3], digest.digest[4]);

				//printf("hash : %s\n", buffer);

				memcpy(buffer + CRYPT_SHA1_DIGEST_LEN, saltString, SALT_LENGTH);
				buffer[CRYPT_SHA1_DIGEST_LEN + SALT_LENGTH] = 0;

				//printf("buffer: %s\n", buffer);

				free(saltedPassword);
				return 1;
			}
		}
	}
	return 0;
}

int ValidatePassword(const char *password, const char* saltedHash) {

	char	hash[CRYPT_SHA1_DIGEST_LEN + 1];
	char	saltString[SALT_LENGTH + 1];

	if (password && saltedHash) {

		char	*saltedPassword;
		size_t	passwordLength = strlen(password);

		memcpy(hash, saltedHash, CRYPT_SHA1_DIGEST_LEN);
		hash[CRYPT_SHA1_DIGEST_LEN] = 0;
		
		memcpy(saltString, saltedHash + CRYPT_SHA1_DIGEST_LEN, SALT_LENGTH);
		saltString[SALT_LENGTH] = 0;

		/*
		printf("hash : %s\n", hash);
		printf("saltString: %s\n", saltString);
		*/


		saltedPassword = (char*)malloc(passwordLength + SALT_LENGTH + 1);
		if (saltedPassword) {

			SHS1_INFO	digest;
			char		hash2[CRYPT_SHA1_DIGEST_LEN + 1];

			snprintf(saltedPassword, passwordLength + SALT_LENGTH + 1, "%s%s", password, saltString);

			//printf("saltedPassword: %s\n", saltedPassword);

			shs1Init(&digest);
			shs1Update(&digest, (BYTE *)saltedPassword, passwordLength + SALT_LENGTH);
			SHS1COUNT(&digest, passwordLength + SALT_LENGTH);
			shs1Final(&digest);

			free(saltedPassword);

			snprintf(hash2, sizeof(hash2), "%08lx%08lx%08lx%08lx%08lx", digest.digest[0], digest.digest[1], digest.digest[2], digest.digest[3], digest.digest[4]);

			//printf("hash2: %s\n", hash2);

			return strcmp(hash, hash2) == 0;
		}
	}

	return 0;
}






void skip_string(FILE *f) {

	fseek(f, fgetc(f) * 256 + fgetc(f), SEEK_CUR);
}



/*********************************************************
 * str_replace()                                         *
 *                                                       *
 * Replace occurrences of 'find' with 'replace' in       *
 * string 'string'. Stop replacing if a replacement      *
 * would cause the string to exceed 'size' bytes         *
 * (including the null terminator). Return the string.   *
 *********************************************************/

typedef char* STR;
typedef const char* CSTR;

#define IS_NOT_NULL(s) ((s) != NULL)

#define str_len(x) strlen((x))


STR str_replace(STR string, size_t size, CSTR find, CSTR replace) {

    STR		ptr = string;
    size_t	left, avail, find_len, replace_len, diff;

	if (IS_NOT_NULL(string) && IS_NOT_NULL(find) && IS_NOT_NULL(replace)) {

		left = str_len(string);
		find_len = str_len(find);
		replace_len = str_len(replace);

		avail = size - (left + 1);
		diff = replace_len - find_len;

		while (left >= find_len) {

			if (strncmp(ptr, find, find_len) != 0) {
				left--;
				ptr++;
				continue;
			}

			if (diff > avail)
				break;

			if (diff != 0)
				memmove(ptr + find_len + diff, ptr + find_len, left + 1);

			strncpy(ptr, replace, replace_len);
			ptr += replace_len;
			left -= find_len;
		}
	}

	return string;
}



#define TOPICMAX		307
#define TOPICSIZE		TOPICMAX + 1

#define DESCMAX			400
#define DESCSIZE		DESCMAX + 1

#define URLMAX			100
#define URLSIZE			URLMAX + 1

#define MAILMAX			100
#define MAILSIZE		MAILMAX + 1

#define WELCOMEMAX		400
#define WELCOMESIZE		WELCOMEMAX + 1


void exportChanData(const char *base_path) {

	FILE		*ifile, *ofileChan, *ofileAccess;
	char		path[4096];
	ChannelInfo	ci;
	AutoKick	*akick;
	ChanAccess	*access;
	char		mlock[32], *mlock_ptr;
	char		escaped_desc[DESCSIZE * 2], escaped_url[URLSIZE * 2], escaped_mail[MAILSIZE * 2], escaped_topic[TOPICSIZE * 2], escaped_welcome[WELCOMESIZE * 2];
	int			chanCount = 0, skipped = 0, ver, i, j;
	int			skipChannel;


	ofileChan = fopen("chan.csv", "w");
	if (!ofileChan)
		fatal("Unable to create chan.csv");

	ofileAccess = fopen("access.csv", "w");
	if (!ofileAccess)
		fatal("Unable to create access.csv");


	#define	CSVHEADER_CHAN		"name,founder,desc,mlock,topic_text,topic_setter,topic_time,url,email,welcome,lang,reg_time\n"
	#define	CSVHEADER_ACC		"chan,nick,level,status\n"

	if (fputs(CSVHEADER_CHAN, ofileChan) < 0)
		fatal("Unable to wrote header to chan.csv");

	if (fputs(CSVHEADER_ACC, ofileAccess) < 0)
		fatal("Unable to wrote header to chan.csv");

	snprintf(path, sizeof(path), "%s/%s", base_path, CHANSERV_DB);
	if (!(ifile = open_db("svcexport-chan", path, "r")))
		return;


	switch (ver = get_file_version(ifile, CHANSERV_DB)) {
	case 8:

		for (i = 0; i < 256; ++i) {

			while (fgetc(ifile) == 1) {

				if (1 != fread(&ci, sizeof(ChannelInfo), 1, ifile))
					fatal("Read error on %s", CHANSERV_DB);


				skipChannel = FlagSet(ci.flags, CI_FROZEN) || FlagSet(ci.flags, CI_SUSPENDED) ||
							  FlagSet(ci.flags, CI_CLOSED) || FlagSet(ci.flags, CI_FORBIDDEN) ||
							  FlagSet(ci.flags, CI_OPERONLY) || FlagSet(ci.flags, CI_SOPONLY) ||
							  FlagSet(ci.flags, CI_SAONLY) || FlagSet(ci.flags, CI_SRAONLY) ||
							  FlagSet(ci.flags, CI_CODERONLY);

				/* Fix vari */

				if (ci.accesscount == 0)
					ci.access = NULL;

				ci.desc = read_string(ifile, CHANSERV_DB);
				if (ci.desc) {

					strncpy(escaped_desc, ci.desc, sizeof(escaped_desc));
					str_replace(escaped_desc, sizeof(escaped_desc), "\"", "\\\"");

				} else
					escaped_desc[0] = 0;

				if (ci.successor)
					skip_string(ifile); //ci.successor = read_string(ifile, CHANSERV_DB);

				if (ci.url) {

					ci.url = read_string(ifile, CHANSERV_DB);
					strncpy(escaped_url, ci.url, sizeof(escaped_url));
					str_replace(escaped_url, sizeof(escaped_url), "\"", "\\\"");

				} else
					escaped_url[0] = 0;

				if (ci.email) {

					ci.email = read_string(ifile, CHANSERV_DB);
					strncpy(escaped_mail, ci.email, sizeof(escaped_mail));
					str_replace(escaped_mail, sizeof(escaped_mail), "\"", "\\\"");

				} else
					escaped_mail[0] = 0;

				if (ci.mlock_key)
					skip_string(ifile); //ci.mlock_key = //read_string(ifile, CHANSERV_DB);

				if (ci.last_topic) {

					ci.last_topic = read_string(ifile, CHANSERV_DB);
					strncpy(escaped_topic, ci.last_topic, sizeof(escaped_topic));
					str_replace(escaped_topic, sizeof(escaped_topic), "\"", "\\\"");

				} else
					escaped_topic[0] = 0;

				if (ci.welcome) {

					ci.welcome = read_string(ifile, CHANSERV_DB);
					strncpy(escaped_welcome, ci.welcome, sizeof(escaped_welcome));
					str_replace(escaped_welcome, sizeof(escaped_welcome), "\"", "\\\"");

				} else
					escaped_welcome[0] = 0;


				if (ci.hold)
					skip_string(ifile); //ci.hold = //read_string(ifile, CHANSERV_DB);

				if (ci.mark)
					skip_string(ifile); //ci.mark = //ead_string(ifile, CHANSERV_DB);

				if (ci.freeze)
					skip_string(ifile); //ci.freeze = //read_string(ifile, CHANSERV_DB);

				if (ci.forbid)
					skip_string(ifile); //ci.forbid = //read_string(ifile, CHANSERV_DB);

				if (ci.real_founder)
					skip_string(ifile); //ci.real_founder = //read_string(ifile, CHANSERV_DB);

				if (ci.accesscount) {

					access = calloc(sizeof(ChanAccess), ci.accesscount);
					ci.access = access;

					if (ci.accesscount != fread(access, sizeof(ChanAccess), ci.accesscount, ifile))
						fatal("Read error on %s", CHANSERV_DB);

					for (j = 0; j < ci.accesscount; ++j, ++access) {
						access->name = read_string(ifile, CHANSERV_DB);
						skip_string(ifile); //access->creator = read_string(ifile, CHANSERV_DB);
					}


					if (!skipChannel) {

						j = 0;
						access = ci.access;

						while (j < ci.accesscount) {

							switch (access->status) {

								case ACCESS_ENTRY_FREE:
								case ACCESS_ENTRY_EXPIRED:
									break;

								case ACCESS_ENTRY_NICK:
								case ACCESS_ENTRY_MASK:

									fprintf(ofileAccess, "\"%s\",\"%s\",\"%d\",\"%d\"\n",
											ci.name, access->name, access->level, access->status);

									break;
							}

							j++;
							access++;
						}
					} /* !skipChannel */


				} /* if (ci.accesscount) */


				if (ci.akickcount) {

					akick = calloc(sizeof(AutoKick), ci.akickcount);
					ci.akick = akick;

					if (ci.akickcount != fread(akick, sizeof(AutoKick), ci.akickcount, ifile))
						fatal("Read error on %s", CHANSERV_DB);

					for (j = 0; j < ci.akickcount; ++j, ++akick) {

						akick->name = read_string(ifile, CHANSERV_DB);

						if (akick->reason)
							skip_string(ifile); //akick->reason = read_string(ifile, CHANSERV_DB);

						if (akick->creator)
							skip_string(ifile); //akick->creator = read_string(ifile, CHANSERV_DB);
					}
				}		/* if (ci.akickcount) */



				if (!skipChannel) {

					// building up mlock ...

					mlock_ptr = mlock;
					*mlock_ptr = 0;
					RemoveFlag(ci.mlock_on, CMODE_r);

					if (ci.mlock_on || ci.mlock_key || ci.mlock_limit)
						mlock_ptr += snprintf(mlock_ptr, sizeof(mlock), "+%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
						FlagSet(ci.mlock_on, CMODE_c) ? "c" : "",
						FlagSet(ci.mlock_on, CMODE_C) ? "C" : "",
						FlagSet(ci.mlock_on, CMODE_d) ? "d" : "",
						FlagSet(ci.mlock_on, CMODE_i) ? "i" : "",
						(ci.mlock_key) ? "k" : "",
						(ci.mlock_limit) ? "l" : "",
						FlagSet(ci.mlock_on, CMODE_m) ? "m" : "",
						FlagSet(ci.mlock_on, CMODE_M) ? "M" : "",
						FlagSet(ci.mlock_on, CMODE_n) ? "n" : "",
						FlagSet(ci.mlock_on, CMODE_O) ? "O" : "",
						FlagSet(ci.mlock_on, CMODE_p) ? "p" : "",
						FlagSet(ci.mlock_on, CMODE_R) ? "R" : "",
						FlagSet(ci.mlock_on, CMODE_s) ? "s" : "",
						FlagSet(ci.mlock_on, CMODE_t) ? "t" : "",
						FlagSet(ci.mlock_on, CMODE_u) ? "u" : "",
						FlagSet(ci.mlock_on, CMODE_U) ? "U" : "", 
						FlagSet(ci.mlock_on, CMODE_j) ? "j" : "",
						FlagSet(ci.mlock_on, CMODE_B) ? "B" : "");

					if (ci.mlock_off)
						mlock_ptr += snprintf(mlock_ptr, sizeof(mlock), "-%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
						FlagSet(ci.mlock_off, CMODE_c) ? "c" : "",
						FlagSet(ci.mlock_off, CMODE_C) ? "C" : "",
						FlagSet(ci.mlock_off, CMODE_d) ? "d" : "",
						FlagSet(ci.mlock_off, CMODE_i) ? "i" : "",
						FlagSet(ci.mlock_off, CMODE_k) ? "k" : "",
						FlagSet(ci.mlock_off, CMODE_l) ? "l" : "",
						FlagSet(ci.mlock_off, CMODE_m) ? "m" : "",
						FlagSet(ci.mlock_off, CMODE_M) ? "M" : "",
						FlagSet(ci.mlock_off, CMODE_n) ? "n" : "",
						FlagSet(ci.mlock_off, CMODE_O) ? "O" : "",
						FlagSet(ci.mlock_off, CMODE_p) ? "p" : "",
						FlagSet(ci.mlock_off, CMODE_R) ? "R" : "",
						FlagSet(ci.mlock_off, CMODE_s) ? "s" : "",
						FlagSet(ci.mlock_off, CMODE_t) ? "t" : "",
						FlagSet(ci.mlock_off, CMODE_u) ? "u" : "",
						FlagSet(ci.mlock_off, CMODE_U) ? "U" : "",
						FlagSet(ci.mlock_off, CMODE_j) ? "j" : "",
						FlagSet(ci.mlock_off, CMODE_B) ? "B" : "");


					// saving chan data ...

					fprintf(ofileChan, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%ld\",\"%s\",\"%s\",\"%s\",\"%d\",\"%ld\"\n",
					//fprintf(ofileChan, "\"%s\";\"%s\";\"%s\";\"%s\";\"%s\";\"%s\";%d;\"%s\";\"%s\";\"%s\";%d\n",
							//ci.name, ci.founder, ci.desc, mlock, ci.last_topic, ci.last_topic_setter, (unsigned long)ci.last_topic_time, ci.url, ci.email, ci.welcome, EXTRACT_LANG_ID(ci.langID));
							ci.name, ci.founder, escaped_desc, mlock, escaped_topic, ci.last_topic_setter, (unsigned long)ci.last_topic_time, escaped_url, escaped_mail, escaped_welcome, EXTRACT_LANG_ID(ci.langID), (unsigned long)ci.time_registered);

					++chanCount;

				} else
					++skipped;


				// freeing up memory ...

				free(ci.desc);
				if (ci.url) free(ci.url);
				if (ci.email) free(ci.email);
				if (ci.last_topic) free(ci.last_topic);
				if (ci.welcome) free(ci.welcome);

				access = ci.access;
				for (j = 0; j < ci.accesscount; ++j, ++access)
					free(access->name);
				free(ci.access);

				akick = ci.akick;
				for (j = 0; j < ci.akickcount; ++j, ++akick)
					if (akick->name) free(akick->name);
				free(ci.akick);

			}		/* while (fgetc(f) == 1) */
		}			/* for (i) */
		break;		/* case 1, etc. */

	default:
		fatal("Unsupported version number (%d) on %s", ver, CHANSERV_DB);

	}	/* switch (version) */

	printf("Exported %d chans [%d skipped]\n", chanCount, skipped);

	close_db(ifile, CHANSERV_DB);

	fclose(ofileChan);
	fclose(ofileAccess);
}



void exportNickData(int otrs, const char *base_path) {
	char		path[PATH_MAX];
	FILE		*ifile, *ofile;
	NickInfo	ni;
	char		crpytedPW[CRYPTED_PASS_LENGTH + 1];
	int			nickCount = 0, skipped = 0, ver, i, j;
	char 		*password;
	char escaped_mail[MAILSIZE * 2];
	char escaped_mail2[MAILSIZE * 2];
	char saltBytes[3];
	int r1,r2;
	
	if (otrs) {

	    ofile = fopen("nick_otrs.tab", "w");
	    if (!ofile)
		fatal("Unable to create nick_otrs.tab");

	} else {

	    ofile = fopen("nick.csv", "w");
	    if (!ofile)
		fatal("Unable to create nick.csv");

	}
	

	#define	CSVHEADER_NICK		"nick,password,realname,mask,url,email,lang,reg_time,last_seen,email2\n"

	if (!otrs)
	    if (fputs(CSVHEADER_NICK, ofile) < 0)
		fatal("Unable to wrote header to nick.csv");

	snprintf(path, sizeof(path), "%s/%s", base_path, NICKSERV_DB);
	if (!(ifile = open_db("svcexport-nick", path, "r"))) {
		fatal("Unable to open %s", NICKSERV_DB);
	}

	switch (ver = get_file_version(ifile, NICKSERV_DB)) {

		case 7:

			for (i = 65; i < 126; ++i) {
				while (fgetc(ifile) == 1) {

					// loading current data ...
				
					if (1 != fread(&ni, sizeof(NickInfo), 1, ifile))
						fatal("Read error on %s", NICKSERV_DB);

					if (ni.url)
						ni.url = read_string(ifile, NICKSERV_DB);

					if (ni.email) {
					    ni.email = read_string(ifile, NICKSERV_DB);
					    strncpy(escaped_mail, ni.email, sizeof(escaped_mail));
					    str_replace(escaped_mail, sizeof(escaped_mail), "\"", "\\\"");
					} else
					    escaped_mail[0] = 0;

					if (ni.forward)
						ni.forward = read_string(ifile, NICKSERV_DB);
					if (ni.hold)
						ni.hold = read_string(ifile, NICKSERV_DB);
					if (ni.mark)
						ni.mark = read_string(ifile, NICKSERV_DB);
					if (ni.forbid)
						ni.forbid = read_string(ifile, NICKSERV_DB);
					if (ni.freeze)
						ni.freeze = read_string(ifile, NICKSERV_DB);

					if (ni.regemail) {
					    ni.regemail = read_string(ifile, NICKSERV_DB);
					    strncpy(escaped_mail2, ni.regemail, sizeof(escaped_mail2));
					    str_replace(escaped_mail2, sizeof(escaped_mail2), "\"", "\\\"");
					} else
					    escaped_mail2[0] = 0;

					ni.last_usermask = read_string(ifile, NICKSERV_DB);
					ni.last_realname = read_string(ifile, NICKSERV_DB);

					if (ni.accesscount) {
						for (j = 0; j < ni.accesscount; j++)
							skip_string(ifile);
					}


					if (FlagUnset(ni.flags, NI_FORBIDDEN) && FlagUnset(ni.flags, NI_FROZEN)) {

						// crypting password ...
						if (otrs) {

						    /* OTRS PASSWORD HASH */

						    if (strlen(ni.email) < 2)
							fatal("Unable to fetch mail for user: %s", ni.nick);

						    srand(time(NULL));
						    r1 = 65 + (double)rand()*(90-65+1) / RAND_MAX;	
						    srand(time(NULL));
						    r2 = 65 + (double)rand()*(90-65+1) / RAND_MAX;	
						    sprintf(saltBytes, "%c%c", r1,r2);

						    password = crypt(ni.pass, saltBytes);

						    if (!password)
							    fatal("Failed to crypt password %s", ni.pass);

						    strcpy(crpytedPW, password);


						    // exporting data ...

						    fprintf(ofile, "%s\t%s\t%s\n",
								ni.nick, crpytedPW, escaped_mail);
						} else {

						    /* STANDARD PASSWORD HASH */
						    if (!CryptPassword(ni.pass, crpytedPW, sizeof(crpytedPW)))
							    fatal("Failed to crypt password %s", ni.pass);

						    // test
						    if (!ValidatePassword(ni.pass, crpytedPW))
							    fatal("Failed crypt crypted password verification! (%s <> %s)", crpytedPW, ni.pass);

						    // exporting data ...

						    fprintf(ofile, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%ld\",\"%ld\",\"%s\"\n",
								ni.nick, crpytedPW, ni.last_realname, ni.last_usermask, ni.url, escaped_mail, EXTRACT_LANG_ID(ni.langID), (unsigned long)ni.time_registered, (unsigned long)ni.last_seen, escaped_mail2);
						}
						

						++nickCount;

					} else
						++skipped;

					// freeing up memory ...

					free(ni.url);
					free(ni.email);
					free(ni.forward);
					free(ni.hold);
					free(ni.mark);
					free(ni.forbid);
					free(ni.freeze);
					free(ni.regemail);
					free(ni.last_usermask);
					free(ni.last_realname);
				}
			}
			break;

		default:
			fatal("Unsupported version number (%d) on %s", ver, NICKSERV_DB);
	}


	printf("Exported %d nicks [%d skipped]\n", nickCount, skipped);

	close_db(ifile, NICKSERV_DB);
	fclose(ofile);
}





/* Main routine. */

void export_dbs(const char *base_path) {
	rnd_init();
	exportNickData(0, base_path);
	exportChanData(base_path);
	rnd_done();
}

/*int main(int ac, char **av, char **envp) {
	int i,otrs = 0;
	clock_t start, end;
	double elapsed;
	
	// start time 
	start = clock();
	
	// OTRS check (-o -O) 
	if (ac>1)
	    for (i = 1; i < ac; ++i) {
		if (!strcmp(av[i],"-o") || !strcmp(av[i],"-O"))
		    otrs = 1;
	     }

	rnd_init();
	     
	if (otrs)
	    printf("* Exporting with OTRS Ticket System password support\n");
	else
	    printf("* Exporting with standard method\n");

	exportNickData(otrs);

	if (!otrs)
	    exportChanData();

	rnd_done();

	// end time 
	end = clock();
	
	elapsed = ((double) (end - start)) / CLOCKS_PER_SEC;
	
	printf("* Finished in %f seconds\n", elapsed);
	
	return 0;
}
*/
