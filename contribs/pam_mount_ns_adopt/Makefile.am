#
# Makefile for pam_mount_ns_adopt
#

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -fPIC -I$(top_srcdir) -I$(top_srcdir)/src/common
# -DLIBSLURM_SO=\"$(libdir)/libslurm.so\"
PLUGIN_FLAGS = -module -rdynamic --export-dynamic -avoid-version

pkglibdir = $(PAM_DIR)

if HAVE_PAM
pam_lib = pam_mount_ns_adopt.la
else
pam_lib =
endif

pkglib_LTLIBRARIES = $(pam_lib)

if HAVE_PAM

current = $(SLURM_API_CURRENT)
age     = $(SLURM_API_AGE)
rev     = $(SLURM_API_REVISION)

pam_mount_ns_adopt_la_SOURCES = pam_mount_ns_adopt.c

pam_mount_ns_adopt_la_LIBADD = \
  $(top_builddir)/src/api/libslurm.la \
  $(top_builddir)/src/common/assoc_mgr.lo -lm \
  $(top_builddir)/src/common/pack.lo -lm \
  $(top_builddir)/src/common/slurm_protocol_api.lo -lm \
  $(top_builddir)/src/common/bitstring.lo -lm \
  $(top_builddir)/src/common/parse_config.lo -lm \
  $(top_builddir)/src/common/slurm_protocol_defs.lo -lm \
  $(top_builddir)/src/common/callerid.lo -lm \
  $(top_builddir)/src/common/parse_time.lo -lm \
  $(top_builddir)/src/common/slurm_protocol_pack.lo -lm \
  $(top_builddir)/src/common/cbuf.lo -lm \
  $(top_builddir)/src/common/parse_value.lo -lm \
  $(top_builddir)/src/common/slurm_protocol_socket_implementation.lo -lm \
  $(top_builddir)/src/common/checkpoint.lo -lm \
  $(top_builddir)/src/common/plugin.lo -lm \
  $(top_builddir)/src/common/slurm_protocol_util.lo -lm \
  $(top_builddir)/src/common/cpu_frequency.lo -lm \
  $(top_builddir)/src/common/plugrack.lo -lm \
  $(top_builddir)/src/common/slurm_resource_info.lo -lm \
  $(top_builddir)/src/common/daemonize.lo -lm \
  $(top_builddir)/src/common/plugstack.lo -lm \
  $(top_builddir)/src/common/slurm_rlimits_info.lo -lm \
  $(top_builddir)/src/common/eio.lo -lm \
  $(top_builddir)/src/common/power.lo -lm \
  $(top_builddir)/src/common/slurm_route.lo -lm \
  $(top_builddir)/src/common/entity.lo -lm \
  $(top_builddir)/src/common/print_fields.lo -lm \
  $(top_builddir)/src/common/slurm_selecttype_info.lo -lm \
  $(top_builddir)/src/common/env.lo -lm \
  $(top_builddir)/src/common/proc_args.lo -lm \
  $(top_builddir)/src/common/slurm_step_layout.lo -lm \
  $(top_builddir)/src/common/fd.lo -lm \
  $(top_builddir)/src/common/read_config.lo -lm \
  $(top_builddir)/src/common/slurm_time.lo -lm \
  $(top_builddir)/src/common/forward.lo -lm \
  $(top_builddir)/src/common/safeopen.lo -lm \
  $(top_builddir)/src/common/slurm_topology.lo -lm \
  $(top_builddir)/src/common/global_defaults.lo -lm \
  $(top_builddir)/src/common/slurm_accounting_storage.lo -lm \
  $(top_builddir)/src/common/stepd_api.lo -lm \
  $(top_builddir)/src/common/gres.lo -lm \
  $(top_builddir)/src/common/slurm_acct_gather_energy.lo -lm \
  $(top_builddir)/src/common/strlcpy.lo -lm \
  $(top_builddir)/src/common/hostlist.lo -lm \
  $(top_builddir)/src/common/slurm_acct_gather_filesystem.lo -lm \
  $(top_builddir)/src/common/strnatcmp.lo -lm \
  $(top_builddir)/src/common/io_hdr.lo -lm \
  $(top_builddir)/src/common/slurm_acct_gather_interconnect.lo -lm \
  $(top_builddir)/src/common/switch.lo -lm \
  $(top_builddir)/src/common/job_options.lo -lm \
  $(top_builddir)/src/common/slurm_acct_gather.lo -lm \
  $(top_builddir)/src/common/timers.lo -lm \
  $(top_builddir)/src/common/job_resources.lo -lm \
  $(top_builddir)/src/common/slurm_acct_gather_profile.lo -lm \
  $(top_builddir)/src/common/uid.lo -lm \
  $(top_builddir)/src/common/layout.lo -lm \
  $(top_builddir)/src/common/slurm_auth.lo -lm \
  $(top_builddir)/src/common/util-net.lo -lm \
  $(top_builddir)/src/common/layouts_mgr.lo -lm \
  $(top_builddir)/src/common/slurm_cred.lo -lm \
  $(top_builddir)/src/common/working_cluster.lo -lm \
  $(top_builddir)/src/common/list.lo -lm \
  $(top_builddir)/src/common/slurmdbd_defs.lo -lm \
  $(top_builddir)/src/common/write_labelled_message.lo -lm \
  $(top_builddir)/src/common/log.lo -lm \
  $(top_builddir)/src/common/slurmdb_defs.lo -lm \
  $(top_builddir)/src/common/xassert.lo -lm \
  $(top_builddir)/src/common/mapping.lo -lm \
  $(top_builddir)/src/common/slurmdb_pack.lo -lm \
  $(top_builddir)/src/common/mpi.lo -lm \
  $(top_builddir)/src/common/slurm_errno.lo -lm \
  $(top_builddir)/src/common/xhash.lo -lm \
  $(top_builddir)/src/common/msg_aggr.lo -lm \
  $(top_builddir)/src/common/slurm_ext_sensors.lo -lm \
  $(top_builddir)/src/common/xlua.lo -lm \
  $(top_builddir)/src/common/net.lo -lm \
  $(top_builddir)/src/common/slurm_jobacct_gather.lo -lm \
  $(top_builddir)/src/common/xmalloc.lo -lm \
  $(top_builddir)/src/common/node_conf.lo -lm \
  $(top_builddir)/src/common/slurm_jobcomp.lo -lm \
  $(top_builddir)/src/common/xsignal.lo -lm \
  $(top_builddir)/src/common/node_features.lo -lm \
  $(top_builddir)/src/common/slurm_mcs.lo -lm \
  $(top_builddir)/src/common/xstring.lo -lm \
  $(top_builddir)/src/common/node_select.lo -lm \
  $(top_builddir)/src/common/slurm_persist_conn.lo -lm \
  $(top_builddir)/src/common/xtree.lo -lm \
  $(top_builddir)/src/common/optz.lo -lm \
  $(top_builddir)/src/common/slurm_priority.lo -lm

pam_mount_ns_adopt_la_LDFLAGS = $(SO_LDFLAGS) $(PLUGIN_FLAGS) $(LIB_LDFLAGS)

force:
$(pam_mount_ns_adopt_la_LIBADD) : force
	@cd `dirname $@` && $(MAKE)
#	Don't specify basename or version.map files in src/api will not be built
#	@cd `dirname $@` && $(MAKE) `basename $@`

else
EXTRA_pam_mount_ns_adopt_la_SOURCES = pam_mount_ns_adopt.c
endif
