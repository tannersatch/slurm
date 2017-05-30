# Makefile for task/mount_isolation plugin

AUTOMAKE_OPTIONS = foreign

PLUGIN_FLAGS = -module -avoid-version --export-dynamic

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/common

pkglib_LTLIBRARIES = task_mount_isolation.la

# Null task plugin.
task_mount_isolation_la_SOURCES = task_mount_isolation.c
task_mount_isolation_la_LDFLAGS = $(SO_LDFLAGS) $(PLUGIN_FLAGS)
