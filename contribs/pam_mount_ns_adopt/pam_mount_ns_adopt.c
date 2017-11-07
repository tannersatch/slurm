/*****************************************************************************\
 *  pam_mount_ns_adopt.c - Adopt incoming connections into job mount namespace
 *****************************************************************************
 *  Copyright (C) 2015, Brigham Young University
 *  Author:  Tanner Satchwell <tannersatch@gmail.com>
 *
 *  This file is part of SLURM, a resource management program.
 *  For details, see <https://slurm.schedmd.com/>.
 *  Please also read the included file: DISCLAIMER.
 *
 *  SLURM is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two. You must obey the GNU
 *  General Public License in all respects for all of the code used other than
 *  OpenSSL. If you modify file(s) with this exception, you may extend this
 *  exception to your version of the file(s), but you are not obligated to do
 *  so. If you do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source files in
 *  the program, then also delete it here.
 *
 *  SLURM is distributed in the hope that it will be useful, but WITHOUT ANY
 *  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with SLURM; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA.
\*****************************************************************************/


#ifndef PAM_MODULE_NAME
#  define PAM_MODULE_NAME "pam PAM_MOUNT_NS_ADOPT"
#endif

#if HAVE_CONFIG_H
#  include "config.h"
#endif

#define PATH_MAX 1024
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <sched.h>
#include <sys/mount.h>
#include <inttypes.h>

#include "slurm/slurm.h"
#include "src/common/slurm_xlator.h"
#include "src/common/slurm_protocol_api.h"
#include "src/common/xcgroup_read_config.c"
#include "src/slurmd/common/xcgroup.c"
#include "src/common/stepd_api.h"


/**********************************\
 *  Session Management Functions  *
\**********************************/

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	/* declare needed variables */
	uint16_t protocol_version;
	job_info_msg_t * job_ptr;
	uint32_t * job_id = NULL;
	uint32_t * pids = NULL;
	uint32_t count = 0;
	struct passwd * pw;
	char mountns[PATH_MAX];
	char * nodename = NULL;
	char * user;
	pid_t user_pid;
	pid_t job_pid;
	uid_t user_id;
	void * dummy;
	int step_id = 0;
	int rc = 0;
	int fd1;
	int fd2;
	int i;


	/* get the user_id of the connecting user */
	rc = pam_get_item(pamh, PAM_USER, (const void **) &dummy);
	user = (char *) dummy;
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: getting uid for user %s", PAM_MODULE_NAME, user);
	if ((rc != PAM_SUCCESS) || (user == NULL) || (*user == '\0')) {
		syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: unable to identify user: %s", PAM_MODULE_NAME, pam_strerror(pamh, rc));
		return(PAM_USER_UNKNOWN);
	}
	if (!(pw = getpwnam(user))) {
		syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: user %s does not exist", PAM_MODULE_NAME, user);
		return(PAM_USER_UNKNOWN);
	}
	user_id = pw->pw_uid;
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: uid = %d", PAM_MODULE_NAME, user_id);


	/* get the node name of the node the user is connecting to */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: acquiring nodename", PAM_MODULE_NAME);
	if (!(nodename = slurm_conf_get_aliased_nodename())) {
		/* if no match, try localhost (Should only be valid in a test environment) */
		if (!(nodename = slurm_conf_get_nodename("localhost"))) {
			syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: no hostname found", PAM_MODULE_NAME);
			return (PAM_SUCCESS);
		}
	}
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: nodename = %s", PAM_MODULE_NAME, nodename);


	/* get the pid of the connecting user */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: acquiring pid", PAM_MODULE_NAME);
	user_pid = getpid();
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: user pid = %d", PAM_MODULE_NAME, user_pid);


	/* find a job id that the connecting user is running */
	rc = slurm_load_job_user(&job_ptr, user_id, SHOW_ALL);
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: slurm_load_job_user rc = %d", PAM_MODULE_NAME, rc);
	if (rc) {
		syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: unable to get jobid", PAM_MODULE_NAME);
		return (PAM_SUCCESS);
	}
	for (i = 0; i < job_ptr->record_count; i++) {
		job_info_t *j = &job_ptr->job_array[i];
		if (j->job_state == JOB_RUNNING) {
			job_id = j->job_id;
			break;
		}
	}
	slurm_free_job_info_msg(job_ptr);


	/* connect to stepd to get job information */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: connecting to stepd", PAM_MODULE_NAME);
	fd1 = stepd_connect(NULL, nodename, *job_id, step_id, &protocol_version);
	if (fd1 == -1) {
		if (errno == ENOENT) {
			syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: job step %u.%u does not exist on this node.", PAM_MODULE_NAME, *job_id, step_id);
		} else {
			syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: unable to connect to slurmstepd", PAM_MODULE_NAME);
		}
		close(fd1);
		return (PAM_SUCCESS);
	}

	/* get a list of job pids, just use the first pid that isn't the incoming connection */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: getting pids", PAM_MODULE_NAME);
	stepd_list_pids(fd1, protocol_version, &pids, &count);
	for (i =0; i < count; i++) {
		if (pids[i] != user_pid) {
			job_pid = pids[i];
			break;
		}
	}

	/* prepare the path of the job mount ns */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: building mnt namespace path", PAM_MODULE_NAME);
	snprintf(mountns, PATH_MAX, "/proc/%d/ns/mnt", job_pid);

	/* open and connect to the job mount ns */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: opening mnt namespace", PAM_MODULE_NAME);
	fd2 = open(mountns, O_RDONLY);
	if (fd2 == -1) {
		syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: failed to open '/proc/PID/ns/mnt", PAM_MODULE_NAME);
		close(fd1);
		close(fd2);
		return (PAM_SUCCESS);
	}

	/* adopt the user into the job mnt namespace */
	syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: adopting user into mnt namespace", PAM_MODULE_NAME);
	if (setns(fd2, 0) == -1) {
		syslog(LOG_MAKEPRI(LOG_AUTH, LOG_INFO), "%s: setns failed to adopt user into jobid mnt ns", PAM_MODULE_NAME);
		close(fd1);
		close(fd2);
		return (PAM_SUCCESS);
	}

	close(fd1);
	close(fd2);
	return 0;
}


PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
	return (PAM_SUCCESS);
}


#ifdef PAM_STATIC
struct pam_module _pam_mount_ns_adopt_modstruct = {
	PAM_MODULE_NAME,
	NULL,
	NULL,
	NULL,
	pam_sm_open_session,
	NULL,
	NULL,
};
#endif
