noinst_PROGRAMS = smb2-cat-async smb2-cat-sync \
	smb2-ftruncate-sync \
	smb2-ls-async smb2-ls-sync \
	smb2-put-sync \
	smb2-raw-fsstat-async \
	smb2-raw-getsd-async \
	smb2-raw-stat-async \
	smb2-stat-sync \
	smb2-statvfs-sync \
	smb2-truncate-sync

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

COMMON_LIBS = ../lib/libsmb2.la -lpopt
smb2_cat_async_LDADD = $(COMMON_LIBS)
smb2_cat_sync_LDADD = $(COMMON_LIBS)
smb2_ftruncate_sync_LDADD = $(COMMON_LIBS)
smb2_ls_async_LDADD = $(COMMON_LIBS)
smb2_ls_sync_LDADD = $(COMMON_LIBS)
smb2_put_sync_LDADD = $(COMMON_LIBS)
smb2_raw_fsstat_async_LDADD = $(COMMON_LIBS)
smb2_raw_getsd_async_LDADD = $(COMMON_LIBS)
smb2_raw_stat_async_LDADD = $(COMMON_LIBS)
smb2_stat_sync_LDADD = $(COMMON_LIBS)
smb2_statvfs_sync_LDADD = $(COMMON_LIBS)
smb2_truncate_sync_LDADD = $(COMMON_LIBS)
