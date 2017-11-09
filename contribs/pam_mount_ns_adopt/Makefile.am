#
# Makefile for pam_mount_ns_adopt
#

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -fPIC -I$(top_srcdir) -I$(top_srcdir)/src/common
# -DLIBSLURM_SO=\"$(libdir)/libslurm.so\"
PLUGIN_FLAGS = -module --export-dynamic -avoid-version

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
  $(top_builddir)/src/common/assoc_mgr.lo \
  $(top_builddir)/src/common/pack.lo \
  $(top_builddir)/src/common/slurm_protocol_api.lo \
  $(top_builddir)/src/common/bitstring.lo \
  $(top_builddir)/src/common/parse_config.lo \
  $(top_builddir)/src/common/slurm_protocol_defs.lo \
  $(top_builddir)/src/common/callerid.lo \
  $(top_builddir)/src/common/parse_time.lo \
  $(top_builddir)/src/common/slurm_protocol_pack.lo \
  $(top_builddir)/src/common/cbuf.lo \
  $(top_builddir)/src/common/parse_value.lo \
  $(top_builddir)/src/common/slurm_protocol_socket_implementation.lo \
  $(top_builddir)/src/common/checkpoint.lo \
  $(top_builddir)/src/common/plugin.lo \
  $(top_builddir)/src/common/slurm_protocol_util.lo \
  $(top_builddir)/src/common/cpu_frequency.lo \
  $(top_builddir)/src/common/plugrack.lo \
  $(top_builddir)/src/common/slurm_resource_info.lo \
  $(top_builddir)/src/common/daemonize.lo \
  $(top_builddir)/src/common/plugstack.lo \
  $(top_builddir)/src/common/slurm_rlimits_info.lo \
  $(top_builddir)/src/common/eio.lo \
  $(top_builddir)/src/common/power.lo \
  $(top_builddir)/src/common/slurm_route.lo \
  $(top_builddir)/src/common/entity.lo \
  $(top_builddir)/src/common/print_fields.lo \
  $(top_builddir)/src/common/slurm_selecttype_info.lo \
  $(top_builddir)/src/common/env.lo \
  $(top_builddir)/src/common/proc_args.lo \
  $(top_builddir)/src/common/slurm_step_layout.lo \
  $(top_builddir)/src/common/fd.lo \
  $(top_builddir)/src/common/read_config.lo \
  $(top_builddir)/src/common/slurm_time.lo \
  $(top_builddir)/src/common/forward.lo \
  $(top_builddir)/src/common/safeopen.lo \
  $(top_builddir)/src/common/slurm_topology.lo \
  $(top_builddir)/src/common/global_defaults.lo \
  $(top_builddir)/src/common/slurm_accounting_storage.lo \
  $(top_builddir)/src/common/stepd_api.lo \
  $(top_builddir)/src/common/gres.lo \
  $(top_builddir)/src/common/slurm_acct_gather_energy.lo \
  $(top_builddir)/src/common/strlcpy.lo \
  $(top_builddir)/src/common/hostlist.lo \
  $(top_builddir)/src/common/slurm_acct_gather_filesystem.lo \
  $(top_builddir)/src/common/strnatcmp.lo \
  $(top_builddir)/src/common/io_hdr.lo \
  $(top_builddir)/src/common/slurm_acct_gather_interconnect.lo \
  $(top_builddir)/src/common/switch.lo \
  $(top_builddir)/src/common/job_options.lo \
  $(top_builddir)/src/common/slurm_acct_gather.lo \
  $(top_builddir)/src/common/timers.lo \
  $(top_builddir)/src/common/job_resources.lo \
  $(top_builddir)/src/common/slurm_acct_gather_profile.lo \
  $(top_builddir)/src/common/uid.lo \
  $(top_builddir)/src/common/layout.lo \
  $(top_builddir)/src/common/slurm_auth.lo \
  $(top_builddir)/src/common/util-net.lo \
  $(top_builddir)/src/common/layouts_mgr.lo \
  $(top_builddir)/src/common/slurm_cred.lo \
  $(top_builddir)/src/common/working_cluster.lo \
  $(top_builddir)/src/common/list.lo \
  $(top_builddir)/src/common/slurmdbd_defs.lo \
  $(top_builddir)/src/common/write_labelled_message.lo \
  $(top_builddir)/src/common/log.lo \
  $(top_builddir)/src/common/slurmdb_defs.lo \
  $(top_builddir)/src/common/xassert.lo \
  $(top_builddir)/src/common/mapping.lo \
  $(top_builddir)/src/common/slurmdb_pack.lo \
  $(top_builddir)/src/common/mpi.lo \
  $(top_builddir)/src/common/slurm_errno.lo \
  $(top_builddir)/src/common/xhash.lo \
  $(top_builddir)/src/common/msg_aggr.lo \
  $(top_builddir)/src/common/slurm_ext_sensors.lo \
  $(top_builddir)/src/common/xlua.lo \
  $(top_builddir)/src/common/net.lo \
  $(top_builddir)/src/common/slurm_jobacct_gather.lo \
  $(top_builddir)/src/common/xmalloc.lo \
  $(top_builddir)/src/common/node_conf.lo \
  $(top_builddir)/src/common/slurm_jobcomp.lo \
  $(top_builddir)/src/common/xsignal.lo \
  $(top_builddir)/src/common/node_features.lo \
  $(top_builddir)/src/common/slurm_mcs.lo \
  $(top_builddir)/src/common/xstring.lo \
  $(top_builddir)/src/common/node_select.lo \
  $(top_builddir)/src/common/slurm_persist_conn.lo \
  $(top_builddir)/src/common/xtree.lo \
  $(top_builddir)/src/common/optz.lo \
  $(top_builddir)/src/common/slurm_priority.lo \
  $(top_builddir)/src/api/job_info.lo \
  $(top_builddir)/src/api/federation_info.lo

pam_mount_ns_adopt_la_LDFLAGS = $(SO_LDFLAGS) $(PLUGIN_FLAGS) $(LIB_LDFLAGS)

force:
$(pam_mount_ns_adopt_la_LIBADD) : force
	@cd `dirname $@` && $(MAKE)
#	Don't specify basename or version.map files in src/api will not be built
#	@cd `dirname $@` && $(MAKE) `basename $@`

else
EXTRA_pam_mount_ns_adopt_la_SOURCES = pam_mount_ns_adopt.c
endif
