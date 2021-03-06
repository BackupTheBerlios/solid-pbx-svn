# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

m4_define([PBX_VERSION],
          m4_bpatsubst(m4_esyscmd([build_tools/make_version .]),
                       [\([0-9.]*\)\(\w\|\W\)*],
                       [\1]))
AC_INIT(asterisk, PBX_VERSION, www.asterisk.org)

# cross-compile macros
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# check existence of the package
AC_CONFIG_SRCDIR([asterisk.c])

# specify output header file
AC_CONFIG_HEADER(include/asterisk/autoconfig.h)

AC_COPYRIGHT("Asterisk")
AC_REVISION($Revision$)

case "${host}" in
     *freebsd*)
     ac_default_prefix=/usr/local
     ;;
     *)
     ac_default_prefix=/usr
     if test ${sysconfdir} = '${prefix}/etc'; then
        sysconfdir=/etc
     fi
     if test ${mandir} = '${prefix}/man'; then
        mandir=/usr/share/man
     fi
     ;;
esac

if test ${localstatedir} = '${prefix}/var'; then
     localstatedir=/var
fi

### ** Platform.
AC_DEFINE_UNQUOTED(PBX_PLATFORM, "${host}",
[Define this to be the canonical name (cpu-vendor-os) of your system.])
AC_DEFINE_UNQUOTED(PBX_CPU, "${host_cpu}",
[Define this to be the name of the CPU of your system.])
AC_DEFINE_UNQUOTED(PBX_VENDOR, "${host_vendor}",
[Define this to be the name of the vendor of your system.])
AC_DEFINE_UNQUOTED(PBX_OS, "${host_os}",
[Define this to be the name of the OS of your system.])

# export some useful defines
PBX_PLATFORM=${host}
PBX_CPU=${host_cpu}
PBX_VENDOR=${host_vendor}
PBX_OS=${host_os}
AC_SUBST(PBX_PLATFORM)
AC_SUBST(PBX_CPU)
AC_SUBST(PBX_VENDOR)
AC_SUBST(PBX_OS)

#  check for uname
AC_PATH_TOOL([UNAME], [uname], No)
if test ! x"${UNAME}" = xNo; then
   PBX_OSREV=$(${UNAME} -r)
fi
AC_SUBST(PBX_OSREV)

# guest OS type
case "${host}" in
  cygwin*|mingw*|windows*|winnt)
    AC_DEFINE(Win32, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="CYGWIN"
# this is ugly - KPF
  OSISWIN32=1
  AC_SUBST(OSISWIN32)
    ;;
  *linux*)
    AC_DEFINE(Linux, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="Linux"
    ;;
  *netbsd*)
    AC_DEFINE(NetBSD, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="NetBSD"
    ;;
  *freebsd*)
    AC_DEFINE(FreeBSD, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="FreeBSD"
    # XXX temporary hack to let FreeBSD use the default paths
    # for local stuff. We need a better solution.
    if test x"${CPPFLAGS}" = x; then
        CPPFLAGS="-I /usr/local/include"
    fi
    if test x"${LDFLAGS}" = x; then
        LDFLAGS="-L /usr/local/lib"
    fi
    ;;
  *openbsd*)
    AC_DEFINE(OpenBSD, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="OpenBSD"
    ;;
  *sun*)
    AC_DEFINE(SunOS, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="SunOS"
    ;;
  *darwin*)
    AC_DEFINE(Darwin, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="Darwin"
    ;;
  *)
    AC_DEFINE(Unix, 1,
              [Define according to your operating system type.])
    PBX_OSTYPE="Unix"
   ;;
esac
AC_SUBST(PBX_OSTYPE)

# This needs to be before any macros that use the C compiler
AC_GNU_SOURCE

AH_TOP(
#ifndef ASTERISK_AUTOCONFIG_H
#define ASTERISK_AUTOCONFIG_H

#ifndef MENUSELECT
#include "asterisk/buildopts.h"
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif
)

AH_BOTTOM(
#endif
)

# cross-compile checks
if test x"${build}" != x"${host}"; 
then
   AC_CHECK_TOOL(CC, gcc, :)
   AC_CHECK_TOOL(CXX, g++, :)
   AC_CHECK_TOOL(RANLIB, ranlib, :)
   AC_CHECK_TOOL(AR, ar, :)

   if test x"${PBX_OSTYPE}" = xWin32;
   then
      AC_CHECK_TOOL(NM, nm, :)
      AC_CHECK_TOOL(WINDRES, windres, :)
      AC_CHECK_TOOL(DLLWRAP, dllwrap, :)
   fi
   crossCompile="Yes"
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_CXXCPP
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AST_CHECK_GNU_MAKE

AC_PATH_PROG([GREP], [grep], :)
AC_PATH_PROG([AR], [ar], :)
AC_PATH_PROG([FIND], [find], :)
AC_PATH_PROG([COMPRESS], [compress], :)
AC_PATH_PROG([BASENAME], [basename], :)
AC_PATH_PROG([DIRNAME], [dirname], :)
AC_PATH_PROG([SHELL], [sh], :)
AC_PATH_PROG([LN], [ln], :)
AC_PATH_PROG([DOT], [dot], :)

AC_LANG(C)

AC_ARG_ENABLE(dev-mode,
	[  --enable-dev-mode    Turn on developer mode],
	[case "${enableval}" in
	      y|ye|yes) AST_DEVMODE=yes ;;
	      n|no)  AST_DEVMODE=no ;;
	      *) AC_MSG_ERROR(bad value ${enableval} for --enable-dev-mode)  ;;
	esac])
AC_SUBST(AST_DEVMODE)

AST_EXT_LIB([asound], [snd_spcm_init], [alsa/asoundlib.h], [ALSA], [Advanced Linux Sound Architecture], [-lm -ldl])
AST_EXT_LIB([curses], [initscr], [curses.h], [CURSES], [curses], [])
AST_EXT_LIB([iksemel], [iks_start_sasl], [iksemel.h], [IKSEMEL], [Iksemel Jabber Library])
AST_EXT_LIB([nbs], [nbs_connect], [nbs.h], [NBS], [Network Broadcast Sound])
AST_EXT_LIB([ncurses], [initscr], [curses.h], [NCURSES], [ncurses], [])
AST_EXT_LIB([newt], [newtBell], [newt.h], [NEWT], [newt])
AST_EXT_LIB([odbc], [SQLConnect], [sql.h], [UNIXODBC], [unixODBC])
AST_EXT_LIB([ogg], [ogg_sync_init], [], [OGG], [OGG])
AST_EXT_LIB([osptk], [OSPPCryptoDecrypt], [osp/osp.h], [OSPTK], [OSP Toolkit], [-lcrypto -lssl])
AST_EXT_LIB([popt], [poptStrerror], [popt.h], [POPT], [popt])
AST_EXT_LIB([pri], [pri_call], [libpri.h], [LIBPRI], [ISDN PRI])
AST_EXT_LIB([radiusclient-ng], [rc_read_config], [radiusclient-ng.h], [RADIUSCLIENT], [Radius Client])
AST_EXT_LIB([speex], [speex_encode], [speex/speex.h], [SPEEX], [Speex], [-lm])
AST_EXT_LIB([sqlite], [sqlite_exec], [sqlite.h], [SQLITE], [SQLite])
AST_EXT_LIB([ssl], [ssl2_connect], [openssl/ssl.h], [OPENSSL], [OpenSSL], [-lcrypto])
AST_EXT_LIB([tds], [tds_version], [tds.h], [FREETDS], [FreeTDS])
AST_EXT_LIB([termcap], [tgetent], [], [TERMCAP], [Termcap])
AST_EXT_LIB([tinfo], [tgetent], [], [TINFO], [Term Info])
AST_EXT_LIB([vorbis], [vorbis_info_init], [vorbis/codec.h], [VORBIS], [Vorbis], [-lm -lvorbisenc])
AST_EXT_LIB([z], [compress], [zlib.h], [ZLIB], [zlib])

EDITLINE_LIBS=""
if test "x$TERMCAP_LIB" != "x" ; then
  EDITLINE_LIBS="$TERMCAP_LIB"
elif test "x$TINFO_LIB" != "x" ; then
  EDITLINE_LIBS="$TINFO_LIB"
elif test "x$CURSES_LIB" != "x" ; then
  EDITLINE_LIBS="$CURSES_LIB"
elif test "x$NCURSES_LIB" != "x" ; then
  EDITLINE_LIBS="$NCURSES_LIB"
else
  echo "*** termcap support not found"
  exit 1
fi
AC_SUBST(EDITLINE_LIBS)

PBX_LIBOSS=0
AC_CHECK_HEADER([linux/soundcard.h],
	        [
		PBX_LIBOSS=1
                AC_DEFINE_UNQUOTED([HAVE_OSS], 1, [Define to indicate the Open Sound System library])
		])
if test "$PBX_LIBOSS" = "0"; then
   AC_CHECK_HEADER([sys/soundcard.h],
                   [
		   PBX_LIBossaudio=1
		   AC_DEFINE_UNQUOTED([HAVE_OSS], 1, [Define to indicate the Open Sound System library])
		   ])
fi
if test "$PBX_LIBOSS" = "0"; then
   AST_EXT_LIB([ossaudio], [oss_ioctl_mixer], [soundcard.h], [OSS], [Open Sound System])
fi

AC_SUBST([PBX_LIBOSS])

if test "${PBX_OSTYPE}" = "Linux" ; then
  AST_EXT_LIB([tonezone], [tone_zone_find], [linux/zaptel.h], [ZAPTEL], [Zaptel])
else
  AST_EXT_LIB([tonezone], [tone_zone_find], [zaptel.h], [ZAPTEL], [Zaptel], [-lm])
fi

GSM_INTERNAL="yes"
GSM_SYSTEM="yes"
AC_ARG_WITH([gsm], AC_HELP_STRING([--with-gsm=PATH], [use libgsm files in PATH, or 'internal']), [
case ${withval} in
     n|no)
     USE_GSM=no
     ;;
     y|ye|yes)
     ;;
     internal)
     GSM_SYSTEM="no"
     ;;
     *)
     GSM_DIR="${withval}"
     GSM_INTERNAL="no"
     ;;
esac
])

PBX_LIBgsm=0

if test "${USE_GSM}" != "no"; then
   if test "${GSM_SYSTEM}" = "yes"; then
      gsmlibdir=""
      if test "x${GSM_DIR}" != "x"; then
         gsmlibdir="-L${GSM_DIR}/lib"
      fi
      AC_CHECK_LIB([gsm], [gsm_create], AC_DEFINE_UNQUOTED([HAVE_GSM], 1,
      [Define to indicate the GSM library]), [], ${gsmlibdir})
      if test "${ac_cv_lib_gsm_gsm_create}" = "yes"; then
	 gsm_LIB="-lgsm"
	 if test "x${GSM_DIR}" != "x"; then
	    gsm_LIB="${gsmlibdir} ${gsm_LIB}"
	    gsm_INCLUDE="-I${GSM_DIR}/include"
	 fi
	 PBX_LIBgsm=1
	 GSM_INTERNAL="no"
      fi
   fi
   if test "${GSM_INTERNAL}" = "yes"; then
      gsm_LIB="internal"
      PBX_LIBgsm=1
   fi
   if test "x${PBX_LIBgsm}" = "x0"; then
      echo "***"
      echo "*** The GSM installation on this system appears to be broken."
      echo "*** Either correct the installation, or run configure"
      echo "*** including --without-gsm"
      exit 1
   fi
fi

AC_SUBST([gsm_LIB])
AC_SUBST([gsm_INCLUDE])
AC_SUBST([PBX_LIBgsm])

AC_ARG_WITH([pq], AC_HELP_STRING([--with-pq=PATH],[use PostgreSQL files in PATH]),[
case ${withval} in
     n|no)
     USE_PQ=no
     ;;
     y|ye|yes)
     PQ_MANDATORY="yes"
     ;;
     *)
     PQ_DIR="${withval}"
     PQ_MANDATORY="yes"
     ;;
esac
])

PBX_LIBpq=0
PG_CONFIG=No
if test "${USE_PQ}" != "no"; then	
   if test "x${PQ_DIR}" != "x"; then
      AC_PATH_TOOL([PG_CONFIG], [pg_config], No, [${PQ_DIR}/bin])
      if test x"${PG_CONFIG}" = xNo; then
         echo "***"
         echo "*** pg_config was not found in the path you specified:"
         echo "*** ${PQ_DIR}/bin"
         echo "*** Either correct the installation, or run configure"
         echo "*** including --without-pq"
         exit 1
      fi
   else
      AC_PATH_TOOL([PG_CONFIG], [pg_config], No)
   fi
fi

if test x"${PG_CONFIG}" != xNo; then
   PQ_libdir=`pg_config --libdir`
   PQ_includedir=`pg_config --includedir`
   
   AC_CHECK_LIB([pq], [PQexec], AC_DEFINE_UNQUOTED([HAVE_PQ], 1,
   [Define to indicate the PostgreSQL library]), [], -L${PQ_libdir} -lz)

   if test "${ac_cv_lib_pq_PQexec}" = "yes"; then
      pq_LIB="-L${PQ_libdir} -lpq -lz"
      pq_INCLUDE="-I${PQ_includedir}"
      PBX_LIBpq=1
   elif test ! -z "${PQ_MANDATORY}";
   then
      echo "***"
      echo "*** The PostgreSQL installation on this system appears to be broken."
      echo "*** Either correct the installation, or run configure"
      echo "*** including --without-pq"
      exit 1
   fi
fi
AC_SUBST([pq_INCLUDE])
AC_SUBST([pq_LIB])
AC_SUBST([PBX_LIBpq])

NETSNMP_LIBS=
PBX_NETSNMP=0
AC_PATH_TOOL([NET_SNMP_CONFIG], [net-snmp-config], No)
if test "x${NET_SNMP_CONFIG}" != "xNo" ; then
  NETSNMP_LIBS=`${NET_SNMP_CONFIG} --agent-libs`
  PBX_NETSNMP=1
fi
AC_SUBST([NETSNMP_LIBS])
AC_SUBST([PBX_NETSNMP])

AC_CHECK_HEADER([linux/ixjuser.h], [PBX_IXJUSER=1], [PBX_IXJUSER=0], [
				   #include <linux/version.h>
				   #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
				   #include <linux/compiler.h>
				   #endif
				   ])
AC_SUBST(PBX_IXJUSER)

AC_LANG_PUSH(C++)

AC_ARG_WITH([vpb], AC_HELP_STRING([--with-vpb=PATH],[use vpb files in PATH]),[
case ${withval} in
     n|no)
     USE_VPB=no
     VPB_MANDATORY="yes"
     ;;
     y|ye|yes)
     ;;
     *)
     VPB_DIR="${withval}"
     VPB_MANDATORY="yes"
     ;;
esac
])
if test "${USE_VPB}" != "no"; then
   echo -n "checking for vpb_open in -lvpb... "
   saved_libs="${LIBS}"
   saved_cppflags="${CPPFLAGS}"
   if test "x${VPB_DIR}" != "x"; then
      LIBS="${LIBS} -L${VPB_DIR}/lib"
      CPPFLAGS="${CPPFLAGS} -I${VPB_DIR}/include"
   fi
   LIBS="${LIBS} -lvpb -lpthread"
   AC_LINK_IFELSE(
	[
	AC_LANG_PROGRAM(
	[#include <vpbapi.h>],
	[int q = vpb_open(0,0);])
	],
	[	AC_MSG_RESULT(yes) 
		ac_cv_lib_vpb_vpb_open="yes" 
	],
	[	AC_MSG_RESULT(no) 
		ac_cv_lib_vpb_vpb_open="no" 
	]
	)
   LIBS="${saved_libs}"
   CPPFLAGS="${saved_cppflags}"
   PBX_LIBvpb=0
   if test "${ac_cv_lib_vpb_vpb_open}" = "yes"; then
	VPB_LIB="-lvpb"
	if test "${VPB_DIR}" != ""; then
	   VPB_LIB="-L${VPB_DIR}/lib ${VPB_LIB}"
	   VPB_INCLUDE="-I${VPB_DIR}/include"
	   AC_SUBST([VPB_INCLUDE])
	fi
	AC_SUBST([VPB_LIB])
	PBX_LIBvpb=1
	AC_DEFINE([HAVE_LIBVPB], 1, [Define if your system has the VoiceTronix (vpb) libraries.])
   elif test ! -z "${VPB_MANDATORY}"; 
   then
      echo "***"
      echo "*** The VoiceTronix (vpb) installation on this system appears to be broken."
      echo "*** Either correct the installation, or run configure"
      echo "*** including --without-vpb."
      exit 1
   fi
fi
AC_SUBST([PBX_LIBvpb])

AC_ARG_WITH([qt], AC_HELP_STRING([--with-qt=PATH],[use Qt files in PATH]),[
case ${withval} in
     n|no)
     USE_QT=no
     QT_MANDATORY="yes"
     ;;
     y|ye|yes)
     ;;
     *)
     QT_DIR="${withval}"
     QT_MANDATORY="yes"
     ;;
esac
])

PBX_QT=0
if test "${USE_QT}" != "no"; then
   echo -n "checking for QDate in -lqt... "
   saved_libs="${LIBS}"
   saved_cppflags="${CPPFLAGS}"
   if test "x${QT_DIR}" != "x"; then
      LIBS="${LIBS} -L${QT_DIR}/lib"
      CPPFLAGS="${CPPFLAGS} -I${QT_DIR}/include"
   fi
   LIBS="${LIBS} -lqt"
   qtlib="qt"
   AC_LINK_IFELSE(
	[
		AC_LANG_PROGRAM(
		[#include <qt3/qdatetime.h>],
		[QDate date();])
	],
	[ac_cv_lib_qt_qt_date="yes"],
	[ac_cv_lib_qt_qt_date="no"])
   LIBS="${saved_libs}"
   CPPFLAGS="${saved_cppflags}"
	
   if test "${ac_cv_lib_qt_qt_date}" = "no"; then
      saved_libs="${LIBS}"
      saved_cppflags="${CPPFLAGS}"
      if test "x${QT_DIR}" != "x"; then
      	 LIBS="${LIBS} -L${QT_DIR}/lib"
	 CPPFLAGS="${CPPFLAGS} -I${QT_DIR}/include"
      fi
      LIBS="${LIBS} -lqt-mt"
      qtlib="qt-mt"	
      AC_LINK_IFELSE(
		[
			AC_LANG_PROGRAM(
			[#include <qt3/qdatetime.h>],
			[QDate date();])
		],
		[ac_cv_lib_qt_qt_date="yes"],
		[ac_cv_lib_qt_qt_date="no"])
      LIBS="${saved_libs}"
      CPPFLAGS="${saved_cppflags}"
   fi	

   if test "${ac_cv_lib_qt_qt_date}" = "yes"; then
      AC_MSG_RESULT(yes) 
   else
      AC_MSG_RESULT(no) 
   fi
	
   if test "${ac_cv_lib_qt_qt_date}" = "yes"; then
      QT_LIB="-l${qtlib}"
      if test "${QT_DIR}" != ""; then
      	 QT_LIB="-L${QT_DIR}/lib ${QT_LIB}"
	 QT_INCLUDE="-I${QT_DIR}/include"
	 AC_SUBST([QT_INCLUDE])
      fi
      AC_SUBST([QT_LIB])
      PBX_QT=1
      AC_DEFINE([HAVE_LIBQT], 1, [Define if your system has the Qt library])
      AC_PATH_TOOL(QTMOC, moc, No)
   elif test ! -z "${QT_MANDATORY}"; 
   then
      echo "***"
      echo "*** The Qt installation on this system appears to be broken."
      echo "*** Either correct the installation, or run configure"
      echo "*** including --without-qt."
      exit 1
   fi
fi
AC_SUBST([PBX_QT])

AC_ARG_WITH([kde], AC_HELP_STRING([--with-kde=PATH],[use KDE files in PATH]),[
case ${withval} in
     n|no)
     USE_KDE=no
     KDE_MANDATORY="yes"
     ;;
     y|ye|yes)
     ;;
     *)
     KDE_DIR="${withval}"
     KDE_MANDATORY="yes"
     ;;
esac
])

PBX_KDE=0
if test "${USE_KDE}" != "no"; then
   echo -n "checking for crashHandler in -lkdecore... "
   saved_ldflags="${LDFLAGS}"
   LDFLAGS="-I${KDE_DIR}/include ${LDFLAGS} -L${KDE_DIR}/lib -lkdecore"
	AC_LINK_IFELSE(
	[
		AC_LANG_PROGRAM(
		[#include "kcrash.h"],
		[KCrash::defaultCrashHandler(1);])
	],
	[ac_cv_lib_kde_crash="yes"],
	[ac_cv_lib_kde_crash="no"])
		
	LDFLAGS="${saved_ldflags}"
	
	if test "${ac_cv_lib_kde_crash}" = "yes"; then
		AC_MSG_RESULT(yes) 
	else
		AC_MSG_RESULT(no) 
	fi
	
	if test "${ac_cv_lib_kde_crash}" = "yes"; then
		KDE_LIBS="-lkdecore -lkdeui"
		if test "${KDE_DIR}" != ""; then
			KDE_LIBS="-L${KDE_DIR}/lib ${KDE_LIBS}"
			KDE_INCLUDE="-I${KDE_DIR}/include"
			AC_SUBST([KDE_INCLUDE])
		fi
		AC_SUBST([KDE_LIBS])
		PBX_KDE=1
		AC_DEFINE([HAVE_LIBKDE], 1, [Define if your system has the KDE library])
   elif test ! -z "${KDE_MANDATORY}"; 
   then
      echo "***"
      echo "*** The KDE installation on this system appears to be broken."
      echo "*** Either correct the installation, or run configure"
      echo "*** including --without-kde."
      exit 1
   fi
fi
AC_SUBST([PBX_KDE])

if test x"${PBX_KDE}" = x1; then
	AC_PATH_TOOL(KDEINIT, kdeinit, No)
	if test ! x"${KDEINIT}" = xNo; then
   	KDEDIR=$(${DIRNAME} ${KDEINIT})
   	KDEDIR=$(${DIRNAME} ${KDEDIR})
	fi
	AC_SUBST([KDEDIR])
fi

AC_LANG_POP

PBX_GTK=0
AC_CHECK_TOOL(GTKCONFIG, gtk-config, No)
if test ! "x${GTKCONFIG}" = xNo; then
   GTK_INCLUDE=$(${GTKCONFIG} --cflags gthread)
   GTK_LIBS=$(${GTKCONFIG} --libs gthread)
   PBX_GTK=1
   AC_DEFINE([HAVE_GTK], 1, [Define if your system has the GTK libraries.])
fi
AC_SUBST(PBX_GTK)
AC_SUBST(GTK_INCLUDE)
AC_SUBST(GTK_LIBS)

PBX_CURL=0
AC_PATH_TOOL([CURL], [curl-config], No)
if test ! x"${CURL}" = xNo; then
# check for version
   CURLLIBS=$(${CURL} --libs)
   PBX_CURL=1
   AC_DEFINE([HAVE_CURL], 1, [Define if your system has the curl libraries.])
fi
AC_SUBST(PBX_CURL)
AC_SUBST(CURLLIBS)

AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h locale.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h termios.h unistd.h utime.h])

AC_SYS_LARGEFILE

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_HEADER_TIME
AC_STRUCT_TM
AC_C_VOLATILE
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRCOLL
AC_FUNC_STRFTIME
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit bzero dup2 endpwent floor ftruncate getcwd gethostbyname gethostname gettimeofday inet_ntoa isascii localtime_r memchr memmove memset mkdir munmap pow putenv re_comp regcomp rint select setenv socket sqrt strcasecmp strchr strcspn strdup strerror strncasecmp strndup strnlen strrchr strsep strspn strstr strtol unsetenv utime strtoq strcasestr asprintf vasprintf])

echo -n "checking for compiler atomic operations... "
AC_LINK_IFELSE(
AC_LANG_PROGRAM([], [int foo1; int foo2 = __sync_fetch_and_add(&foo1, 1);]),
AC_MSG_RESULT(yes)
AC_DEFINE([HAVE_GCC_ATOMICS], 1, [Define to 1 if your GCC C compiler provides atomic operations.]),
AC_MSG_RESULT(no)
)

AC_CONFIG_FILES([build_tools/menuselect-deps makeopts])
AC_OUTPUT

echo
echo "               .\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$=..      "
echo "            .\$7\$7..          .7\$\$7:.    "
echo "          .\$\$:.                 ,\$7.7   "
echo "        .\$7.     7\$\$\$\$           .\$\$77  "
echo "     ..\$\$.       \$\$\$\$\$            .\$\$\$7 "
echo "    ..7\$   .?.   \$\$\$\$\$   .?.       7\$\$\$."
echo "   \$.\$.   .\$\$\$7. \$\$\$\$7 .7\$\$\$.      .\$\$\$."
echo " .777.   .\$\$\$\$\$\$77\$\$\$77\$\$\$\$\$7.      \$\$\$,"
echo " \$\$\$~      .7\$\$\$\$\$\$\$\$\$\$\$\$\$7.       .\$\$\$."
echo ".\$\$7          .7\$\$\$\$\$\$\$7:          ?\$\$\$."
echo "\$\$\$          ?7\$\$\$\$\$\$\$\$\$\$I        .\$\$\$7 "
echo "\$\$\$       .7\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$      :\$\$\$. "
echo "\$\$\$       \$\$\$\$\$\$7\$\$\$\$\$\$\$\$\$\$\$\$    .\$\$\$.  "
echo "\$\$\$        \$\$\$   7\$\$\$7  .\$\$\$    .\$\$\$.   "
echo "\$\$\$\$             \$\$\$\$7         .\$\$\$.    "
echo "7\$\$\$7            7\$\$\$\$        7\$\$\$      "
echo " \$\$\$\$\$                        \$\$\$       "
echo "  \$\$\$\$7.                       \$\$  (TM)     "
echo "   \$\$\$\$\$\$\$.           .7\$\$\$\$\$\$  \$\$      "
echo "     \$\$\$\$\$\$\$\$\$\$\$\$7\$\$\$\$\$\$\$\$\$.\$\$\$\$\$\$      "
echo "       \$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$.                "
echo

echo "Package configured for: "
echo " OS type  : $PBX_OSTYPE"
echo " Host CPU : $host_cpu"
if test "x${crossCompile}" = xYes; then
   echo ""
   echo " Cross Compilation = YES"
   echo " Target            = ${host}"
fi

