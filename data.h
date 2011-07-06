/*
*
* Azzurra IRC Services - Export tools
* 
* data.h
* 
*/

#ifndef SVCEXP_DATA_H
#define SVCEXP_DATA_H


void fatal(const char *fmt,...);


/*************************************************************************/

/* Version number for data files; if structures below change, increment
 * this.  (Otherwise -very- bad things will happen!) */

#define FILE_VERSION    8



#define CHANMAX			64
#define NICKMAX			32
#define PASSMAX			32



#define NICKSERV_DB		"nick.db"
#define CHANSERV_DB		"chan.db"

typedef unsigned int		LANG_ID;
typedef unsigned char	NICK_LANG_ID;

#define			EXTRACT_LANG_ID(nick_lid)	( (LANG_ID) (nick_lid) )
#define			COMPACT_LANG_ID(lid)		( (NICK_LANG_ID) (lid & 0xFF) )



/*************************************************************************/

/* Nickname info structure.  Each nick structure is stored in one of 256
 * lists; the list is determined by the first character of the nick.  Nicks
 * are stored in alphabetical order within lists. */

typedef struct nickinfo_ NickInfo;

struct nickinfo_ {

    NickInfo	*next, *prev;
    char		nick[NICKMAX];
    char		pass[PASSMAX];
    char		*last_usermask;
    char		*last_realname;
    time_t		time_registered;
    time_t		last_seen;
    long		accesscount;			/* # of entries */
    char		**access;				/* Array of strings */
    long		flags;					/* See below */
	time_t		last_drop_request;		/* Was id_timestamp */
    unsigned short	memomax;
    short		channelcount;			/* Number of channels nick has access to */
    char		*url;
    char		*email;
    char		*forward;
    char		*hold;       /*  }                                       */
    char		*mark;       /*  }   --   Identities (what svsadmin did it?)  */
    char		*forbid;     /*  }                                       */
    int			news;
    char		*regemail;				/* Original e-mail */
	time_t		last_email_request;		/* Was ICQ number */
    unsigned long auth;
    char		*freeze;
    NICK_LANG_ID	langID;

	unsigned char	reserved[3];		/* For future expansion -- decrease! */
};


#define NI_FORBIDDEN		0x00000004
#define NI_FROZEN			0x00040000



#define RESERVED_NICK	0x00000001
#define RESERVED_CHAN	0x00000002

#define CRNR_VALID		0x0000
#define CRNR_BLOCK		0x0001
#define CRNR_TOKILL		0x0002
#define CRNR_AKILLED	0x0004


/*************************************************************************/

/* Channel info structures.  Stored similarly to the nicks, except that
 * the second character of the channel name, not the first, is used to
 * determine the list.  (Hashing based on the first character of the name
 * wouldn't get very far. ;) ) */

/* Access levels for users. */
typedef struct {
    short	level;

	short	status; /* See ACCESS_ENTRY_* below */
	char	*name;
	char	*creator;
	time_t	creationTime;

} ChanAccess;


#define ACCESS_ENTRY_FREE		0
#define ACCESS_ENTRY_NICK		1
#define ACCESS_ENTRY_MASK		2
#define ACCESS_ENTRY_EXPIRED	3


#define ACCESS_FOUNDER	10000	/* Numeric level indicating founder access */
#define ACCESS_INVALID	-10000	/* Used in levels[] for disabled settings */


/* AutoKick data. */
typedef struct {

    short is_nick;
    short pad;
    char *name;
    char *reason;
	char	*creator;
	time_t	creationTime;

} AutoKick;

typedef struct chaninfo_ ChannelInfo;

struct chaninfo_ {

    ChannelInfo *next, *prev;
    char name[CHANMAX];
    char founder[NICKMAX];				/* Always a reg'd nick */
    char founderpass[PASSMAX];
    char *desc;
    time_t time_registered;
    time_t last_used;
    long accesscount;
    ChanAccess *access;					/* List of authorized users */
    long akickcount;
    AutoKick *akick;
    long mlock_on, mlock_off;			/* See channel modes below */
    long mlock_limit;					/* 0 if no limit */
    char *mlock_key;					/* NULL if no key */
    char *last_topic;					/* Last topic on the channel */
    char last_topic_setter[NICKMAX];	/* Who set the last topic */
    time_t last_topic_time;				/* When the last topic was set */
    long flags;							/* See below */
    char *successor;					
    char *url;
    char *email;
    char *welcome;
    char *hold;       /*  }                                         */
    char *mark;       /*  }   --   Identities (what admin did it?)  */
    char *freeze;     /*  }   --                                    */
    char *forbid;     /*  }                                         */
    int topic_allow;					/* Who's allowed to change topic */
    unsigned long auth;
    long settings;
    char *real_founder;
    time_t last_drop_request;
    NICK_LANG_ID	langID;
    unsigned char	banType;
    unsigned char reserved[2];					/* For future expansion -- decrease! */

};


/* Shaka 13/05/01

  Alcuni valori restituiti da get_access()

  15 Founder
  13 Co-Founder
  10 SOP
   5 AOP
   3 VOP
   ? AKICK

*/
#define CS_ACCESS_FOUNDER		15
#define CS_ACCESS_COFOUNDER		13
#define CS_ACCESS_SOP			10
#define CS_ACCESS_AOP			5
#define CS_ACCESS_VOP			3
#define CS_ACCESS_NONE			0

#define CS_ACCESS_AKICK			20	/* valore impostato arbitrariamente */

#define CS_STATUS_IDCHAN		4
#define CS_STATUS_IDNICK		3
#define CS_STATUS_ACCLIST		2
#define CS_STATUS_MASK			1
#define CS_STATUS_NONE			0

// Shaka 15/05/01 - flag di lock per ci.settings

#define CI_ACCCESS_NO_LOCK			0x00000000
#define CI_ACCCESS_CFOUNDER_LOCK	0x00000001
#define CI_ACCCESS_SOP_LOCK			0x00000002
#define CI_ACCCESS_AOP_LOCK			0x00000004
#define CI_ACCCESS_VOP_LOCK			0x00000008
#define CI_ACCCESS_AKICK_LOCK		0x00000010

// Shaka 06/09/01 - flag per il livello di verbose (ci.settings)

#define CI_NOTICE_VERBOSE_NONE			0x00000000 // 00000000 00000000
#define CI_NOTICE_VERBOSE_CLEAR			0x00000100 // 00000001 00000000
#define CI_NOTICE_VERBOSE_ACCESS		0x00000200 // 00000010 00000000
#define CI_NOTICE_VERBOSE_SET			0x00000300 // 00000011 00000000

#define CI_NOTICE_VERBOSE_MASK      	0x00000300 // 00000011 00000000
#define CI_NOTICE_VERBOSE_RESETMASK 	0x0000FCFF // 11111100 11111111

#define CSMatchVerbose(settings, level)		( ((settings) & CI_NOTICE_VERBOSE_MASK) >= (level) )


#define CI_FORBIDDEN	0x00000080
#define CI_OPERONLY     0x00000800
#define CI_SOPONLY      0x00001000
#define CI_SAONLY       0x00002000
#define CI_SRAONLY      0x00004000
#define CI_CODERONLY    0x00008000
#define CI_FROZEN		0x00020000
#define CI_SUSPENDED    0x01000000
#define CI_CLOSED       0x08000000




// UMODEs

#define UMODE_a 0x00000001
#define UMODE_A 0x00000002
#define UMODE_b 0x00000004
#define UMODE_c 0x00000008
#define UMODE_d 0x00000010
#define UMODE_e 0x00000020
#define UMODE_f 0x00000040
#define UMODE_g 0x00000080
#define UMODE_h 0x00000100
#define UMODE_i 0x00000200
#define UMODE_j 0x00000400
#define UMODE_k 0x00000800
#define UMODE_m 0x00001000
#define UMODE_n 0x00002000
#define UMODE_o 0x00004000
#define UMODE_O 0x00008000
#define UMODE_r 0x00010000
#define UMODE_R 0x00020000
#define UMODE_s 0x00040000
#define UMODE_S 0x00080000
#define UMODE_w 0x00100000
#define UMODE_x 0x00200000
#define UMODE_y 0x00400000
#define UMODE_z 0x00800000
#define UMODE_F 0x01000000

// CMODEs

#define CMODE_i         0x00000001
#define CMODE_m         0x00000002
#define CMODE_n         0x00000004
#define CMODE_p         0x00000008
#define CMODE_s         0x00000010
#define CMODE_t         0x00000020
#define CMODE_k         0x00000040
#define CMODE_l         0x00000080
#define CMODE_r         0x00000100
#define CMODE_C         0x00000200
#define CMODE_R         0x00000400
#define CMODE_c         0x00000800
#define CMODE_O         0x00001000
#define CMODE_U         0x00002000
#define CMODE_M         0x00004000
#define CMODE_u         0x00008000
#define CMODE_S         0x00010000
#define CMODE_d         0x00020000
#define CMODE_j         0x00040000
#define CMODE_B         0x00080000


extern int get_file_version(FILE *f, const char *filename);
extern int write_file_version(FILE *f, const char *filename);
extern FILE *open_db(const char *service, const char *filename, const char *mode);
extern void close_db(FILE *dbfile, const char *filename);
extern void backup_database();
extern char *read_string(FILE *f, const char *filename);
extern char *write_string(const char *s, FILE *f, const char *filename);



#endif /* SVCEXP_DATA_H */
