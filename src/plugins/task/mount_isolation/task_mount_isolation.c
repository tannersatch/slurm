/*****************************************************************************\
 *  task_mount_isolation.c - Create isolated namespaced directories per job
 *****************************************************************************
 *  Copyright (C) 2015, Brigham Young University
 *  Author:  Tanner Satchwell <tannersatch@gmail.com>
 *  Author:  Ryan Cox <ryan_cox@byu.edu>
 *
 *  This file is part of SLURM, a resource management program.
 *  For details, see <http://slurm.schedmd.com/>.
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

#if     HAVE_CONFIG_H
#  include "config.h"
#endif

#define _GNU_SOURCE
#define PATH_MAX 1024
#include <sched.h>
#include <unistd.h>
#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>

#include "slurm/slurm_errno.h"
#include "src/common/slurm_xlator.h"
#include "src/slurmd/slurmstepd/slurmstepd_job.h"
#include "src/slurmd/slurmd/slurmd.h"
#include "src/common/uid.c"

/*
 * These variables are required by the generic plugin interface.  If they
 * are not found in the plugin, the plugin loader will ignore it.
 *
 * plugin_name - a string giving a human-readable description of the
 * plugin.  There is no maximum length, but the symbol must refer to
 * a valid string.
 *
 * plugin_type - a string suggesting the type of the plugin or its
 * applicability to a particular form of data or method of data handling.
 * If the low-level plugin API is used, the contents of this string are
 * unimportant and may be anything.  SLURM uses the higher-level plugin
 * interface which requires this string to be of the form
 *
 *      <application>/<method>
 *
 * where <application> is a description of the intended application of
 * the plugin (e.g., "task" for task control) and <method> is a description
 * of how this plugin satisfies that application.  SLURM will only load
 * a task plugin if the plugin_type string has a prefix of "task/".
 *
 * plugin_version - an unsigned 32-bit integer containing the Slurm version
 * (major.minor.micro combined into a single number).
 */
const char plugin_name[]        = "task MOUNT_ISOLATION plugin";
const char plugin_type[]        = "task/mount_isolation";
const uint32_t plugin_version   = SLURM_VERSION_NUMBER;

/*
 * the main isolate function that sets up the mount namespace
 */
static int _isolate(const stepd_step_rec_t *job);

/*
 * a function to cleanup no longer needed temporary files
 */
static int _job_cleanup(const uint32_t job_id);

/*
 * a function to recursively delete a non-empty directory
 */
static int _remove_directory(const char *path, int64_t *bytes, dev_t device_id);

/*
 * init() is called when the plugin is loaded, before any other functions
 *	are called.  Put global initialization here.
 */
extern int init (void) {
	/* retreive tmp directories and subdirectory from slurm.conf */
	char tmp_dirs[PATH_MAX];
	snprintf(tmp_dirs, PATH_MAX, "%s", slurmctld_conf.task_plugin_tmp_dirs);
	char tmp_subdir[PATH_MAX];
	snprintf(tmp_subdir, PATH_MAX, "%s", slurmctld_conf.task_plugin_tmp_subdir);
	int rc = 0;

	/* prepare to loop through tmp directories */
	char* tmp_dir;
	char* saveptr;
	tmp_dir = strtok_r(tmp_dirs, ",", &saveptr);

	/* look through tmp directories */
	while (tmp_dir) {
		char subdir_path[PATH_MAX];
		snprintf(subdir_path, PATH_MAX, "%s/%s", tmp_dir, tmp_subdir);
		struct stat sb;

		/* make the tmp directory private */
		rc = mount("", tmp_dir, NULL, MS_PRIVATE, NULL);
		if (rc) {
			/* make sure the directory is mounted to itself */
			rc = mount(tmp_dir, tmp_dir, NULL, MS_BIND, NULL);
			if (rc) {
				slurm_error("%s: failed to 'mount --bind %s %s' error: %d", plugin_name, tmp_dir, tmp_dir, rc);
				return SLURM_ERROR;
			}

			/* try again */
			rc = mount("", tmp_dir, NULL, MS_PRIVATE, NULL);
			if (rc) {
				slurm_error("%s: failed to 'mount --make-private %s' error: %d", plugin_name, tmp_dir, rc);
				return SLURM_ERROR;
			}
		}

		/* create tmp subdirectory */
		rc = lstat(subdir_path, &sb);
		if (rc == 0 && S_ISDIR(sb.st_mode)) {
			debug3("%s: failed to create %s temporary subdirectory at %s. warning: %d (directory already exists)", plugin_name, tmp_subdir, subdir_path, rc);
		} else {
			rc = mkdir(subdir_path, 0000);
			if (rc) {
				slurm_error("%s: failed to create %s temporary subdirectory at %s. error: %d", plugin_name, tmp_subdir, subdir_path, rc);
				return SLURM_ERROR;
			}
		}

		/* prepare for next loop */
		tmp_dir = strtok_r(NULL, ",", &saveptr);
		while (tmp_dir && *tmp_dir == '\040') {
			tmp_dir++;
		}
	}

	debug("%s loaded", plugin_name);
	return SLURM_SUCCESS;
}

/*
 * fini() is called when the plugin is removed. Clear any allocated
 *	storage here.
 */
extern int fini (void) {
	return SLURM_SUCCESS;
}

/*
 * task_p_slurmd_batch_request()
 */
extern int task_p_slurmd_batch_request (uint32_t job_id, batch_job_launch_msg_t *req) {
	debug("task_p_slurmd_batch_request: %u", job_id);
	return SLURM_SUCCESS;
}

/*
 * task_p_slurmd_launch_request()
 */
extern int task_p_slurmd_launch_request (uint32_t job_id, launch_tasks_request_msg_t *req, uint32_t node_id) {
	debug("task_p_slurmd_launch_request: %u.%u %u", job_id, req->job_step_id, node_id);
	return SLURM_SUCCESS;
}

/*
 * task_p_slurmd_reserve_resources()
 */
extern int task_p_slurmd_reserve_resources (uint32_t job_id, launch_tasks_request_msg_t *req, uint32_t node_id) {
	debug("task_p_slurmd_reserve_resources: %u %u", job_id, node_id);
	return SLURM_SUCCESS;
}

/*
 * task_p_slurmd_suspend_job()
 */
extern int task_p_slurmd_suspend_job (uint32_t job_id) {
	debug("task_p_slurmd_suspend_job: %u", job_id);
	return SLURM_SUCCESS;
}

/*
 * task_p_slurmd_resume_job()
 */
extern int task_p_slurmd_resume_job (uint32_t job_id) {
	debug("task_p_slurmd_resume_job: %u", job_id);
	return SLURM_SUCCESS;
}

/*
 * task_p_slurmd_release_resources()
 */
extern int task_p_slurmd_release_resources (uint32_t job_id) {
	debug("task_p_slurmd_release_resources: %u", job_id);
	debug3("%s: in task_p_slurmd_release_resources for job: %u", plugin_name, job_id);
	/* return _job_cleanup(job_id); */
	return SLURM_SUCCESS;
}

/*
 * task_p_pre_setuid() is called before setting the UID for the
 * user to launch his jobs. Use this to create the CPUSET directory
 * and set the owner appropriately.
 */
extern int task_p_pre_setuid (stepd_step_rec_t *job) {
	return SLURM_SUCCESS;
}

/*
 * task_p_pre_launch() is called prior to exec of application task.
 *	It is followed by TaskProlog program (from slurm.conf) and
 *	--task-prolog (from srun command line).
 */
extern int task_p_pre_launch (stepd_step_rec_t *job) {
	debug("task_p_pre_launch: %u.%u, task %d", job->jobid, job->stepid, job->envtp->procid);
	return SLURM_SUCCESS;
}

/*
 * task_p_pre_launch_priv() is called prior to exec of application task.
 * in privileged mode, just after slurm_spank_task_init_privileged
 */
extern int task_p_pre_launch_priv (stepd_step_rec_t *job) {
	debug("task_p_pre_launch_priv: %u.%u", job->jobid, job->stepid);
	return _isolate(job);
	/* return SLURM_SUCCESS; */
}

/*
 * task_term() is called after termination of application task.
 *	It is preceded by --task-epilog (from srun command line)
 *	followed by TaskEpilog program (from slurm.conf).
 */
extern int task_p_post_term (stepd_step_rec_t *job, stepd_step_task_info_t *task) {
	debug("task_p_post_term: %u.%u, task %d", job->jobid, job->stepid, task->id);
	return _job_cleanup(job->jobid);
	/* return SLURM_SUCCESS; */
}

/*
 * task_p_post_step() is called after termination of the step
 * (all the task)
 */
extern int task_p_post_step (stepd_step_rec_t *job) {
	return SLURM_SUCCESS;
}

/*
 * Keep track a of a pid.
 */
extern int task_p_add_pid (pid_t pid) {
	return SLURM_SUCCESS;
}


/*
 * _isolate() is called from task_p_pre_launch_priv to setup mount namespace isolation
 */
static int _isolate(const stepd_step_rec_t *job) {
	/* set variables for function */
	int rc = 0;
	char* user = uid_to_string(job->uid);

	/* retreive tmp directories and subdirectory from slurm.conf */
	char tmp_dirs[PATH_MAX];
	snprintf(tmp_dirs, PATH_MAX, "%s", slurmctld_conf.task_plugin_tmp_dirs);
	char tmp_subdir[PATH_MAX];
	snprintf(tmp_subdir, PATH_MAX, "%s", slurmctld_conf.task_plugin_tmp_subdir);

	/* create a new mount namespace */
	rc = unshare(CLONE_NEWNS);
	if (rc) {
		slurm_error("%s: failed to unshare mounts for job: %u error: %d", plugin_name, job->jobid, rc);
		return SLURM_ERROR;
	}

	/* make root in the new namespace a slave so any changes don't propagate back to the default root */
	rc = mount("", "/", NULL, MS_REC|MS_SLAVE, NULL);
	if (rc) {
		slurm_error("%s: failed to 'mount --make-rslave /' for job: %u error: %d", plugin_name, job->jobid, rc);
		return SLURM_ERROR;
	}

	/* prepare to loop through tmp directories */
	char* tmp_dir;
	char* saveptr;
	tmp_dir = strtok_r(tmp_dirs, ",", &saveptr);

	/* loop through tmp directories */
	while (tmp_dir) {
		/* set variables for loop */
		char tmp_user_path[PATH_MAX];
		snprintf(tmp_user_path, PATH_MAX, "%s/%s/%s", tmp_dir, tmp_subdir, user);
		char tmp_job_path[PATH_MAX];
		snprintf(tmp_job_path, PATH_MAX, "%s/%s/%s/%d", tmp_dir, tmp_subdir, user, job->jobid);
		struct stat sb;

		/* create user tmp directory */
		rc = lstat(tmp_user_path, &sb);
		if (rc == 0 && S_ISDIR(sb.st_mode)) {
			debug3("%s: failed to create user directory %s for job: %u warning: %d (directory already exists)", plugin_name, tmp_user_path, job->jobid, rc);
		} else {
			rc = mkdir(tmp_user_path, 0700);
			if (rc) {
				slurm_error("%s: failed to create user directory %s for job: %u error: %d", plugin_name, tmp_user_path, job->jobid, rc);
				return SLURM_ERROR;
			}
		}
	
		/* set permissions on user tmp directory */
		rc = lchown(tmp_user_path, job->uid, job->gid);
		if (rc) {
			slurm_error("%s: failed to change ownership of user directory %s for job: %u error: %d", plugin_name, tmp_user_path, job->jobid, rc);
			return SLURM_ERROR;
		}
		
		/* create job id tmp directory */
		rc = lstat(tmp_job_path, &sb);
		if (rc == 0 && S_ISDIR(sb.st_mode)) {
			debug3("%s: failed to create jobid directory %s for job: %u warning: %d (directory already exists)", plugin_name, tmp_job_path, job->jobid, rc);
		} else {
			rc = mkdir(tmp_job_path, 0700);
			if (rc) {
				slurm_error("%s: failed to create jobid directory %s for job: %u error: %d", plugin_name, tmp_job_path, job->jobid, rc);
				return SLURM_ERROR;
			}
		}
	
		/* set permissions on job id tmp directory */
		rc = lchown(tmp_job_path, job->uid, job->gid);
		if (rc) {
			slurm_error("%s: failed to change ownership of jobid directory %s for job: %u error: %d", plugin_name, tmp_job_path, job->jobid, rc);
			return SLURM_ERROR;
		}
	
		/* bind user and job id isolated directories to tmp directories */
		rc = mount(tmp_job_path, tmp_dir, NULL, MS_BIND, NULL);
		if (rc) {
			slurm_error("%s: failed to mount jobid directory %s to %s for job: %u error: %d", plugin_name, tmp_job_path, tmp_dir, job->jobid, rc);
			return SLURM_ERROR;
		}

		/* prepare for next loop */
		tmp_dir = strtok_r(NULL, ",", &saveptr);
		while (tmp_dir && *tmp_dir == '\040') {
			tmp_dir++;
		}

	}

	return SLURM_SUCCESS;
}

/*
 * _job_cleanup() is called when a job terminates and calls _remove_directory() to remove temporary files related to the temrinated job
 */
static int _job_cleanup(const uint32_t job_id) {
	int rc = 0;
	ListIterator itr = NULL;
	List steps = NULL;
	step_loc_t *stepd = NULL;
	int job_step_cnt = 0;
	int64_t bytes = 0;
	char* nodename;
	uid_t uid = -1;
	int fd;

	/* get the nodename */
	if (!(nodename = slurm_conf_get_aliased_nodename())) {
		slurm_error("%s: failed to get nodename for job: %u error: %d", plugin_name, job_id, rc);
		return SLURM_ERROR;
	}

	steps = stepd_available(NULL, nodename);

	/* count number of running steps for the job and get uid */
	itr = list_iterator_create(steps);
	while ((stepd = list_next(itr))) {
		if (stepd->jobid != job_id) {
			/* multiple jobs expected on shared nodes */
			continue;
		}
		
		/* count number of running steps for the job */
		job_step_cnt++;

		fd = stepd_connect(stepd->directory, stepd->nodename, stepd->jobid, stepd->stepid, &stepd->protocol_version);
		if (fd == -1) {
			debug3("%s: _job_cleanup unable to connect to step %u.%u", plugin_name, stepd->jobid, stepd->stepid);
			continue;
		}
		uid = stepd_get_uid(fd, stepd->protocol_version);

		close(fd);
		if ((int)uid < 0) {
			debug3("%s: _job_cleanup get uid failed %u.%u", plugin_name, stepd->jobid, stepd->stepid);
			continue;
		}
		break;
	}
	list_iterator_destroy(itr);

	/* if this is the last step in the job */
	if (job_step_cnt == 1) {
		/* set necessary variables */
		char* user = uid_to_string(uid);
		struct stat sb;
		/* used to ensure recursive remove stays on the same file system */
		dev_t device_id;

		/* retreive tmp directories and subdirectory from slurm.conf */
		char tmp_dirs[PATH_MAX];
		snprintf(tmp_dirs, PATH_MAX, "%s", slurmctld_conf.task_plugin_tmp_dirs);
		char tmp_subdir[PATH_MAX];
		snprintf(tmp_subdir, PATH_MAX, "%s", slurmctld_conf.task_plugin_tmp_subdir);

		/* prepare to loop through tmp directories */
		char* tmp_dir;
		char* saveptr;
		tmp_dir = strtok_r(tmp_dirs, ",", &saveptr);

		/* loop through tmp directories */
		while (tmp_dir) {
			/* set variables for loop */
			char tmp_job_path[PATH_MAX];
			snprintf(tmp_job_path, PATH_MAX, "%s/%s/%s/%d", tmp_dir, tmp_subdir, user, job_id);
			if (!lstat(tmp_job_path, &sb)) {
				device_id = sb.st_dev;
			}

			rc = _remove_directory(tmp_job_path, &bytes, device_id);
			if (rc) {
				slurm_error("%s: failed to remove job related temporary files for job: %u error: %d", plugin_name, job_id, rc);
				return SLURM_ERROR;
			}

			/* prepare for next loop */
			tmp_dir = strtok_r(NULL, ",", &saveptr);
			while (tmp_dir && *tmp_dir == '\040') {
				tmp_dir++;
			}
		}

		/****** Begin Data Gathering ******/
		info("%s: %ld bytes temporary files purged for jobid %u", plugin_name, bytes, job_id);
		/****** End Data Gathering ******/

	}

	return SLURM_SUCCESS;
}

/*
 * _remove_directory() is called to recursively delete a non-empty directory
 */
static int _remove_directory(const char *path, int64_t *bytes, dev_t device_id) {
	/* declare needed variables */
	DIR *d = opendir(path);
	size_t path_len = strlen(path);
	int r = -1;


	if (d) {
		struct dirent *p;
		r = 0;

		while (!r && (p=readdir(d))) {
			int r2 = -1;
			char *buf;
			size_t len;

			/* skip the names "." and ".." as we don't want to recurse on them. */
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
				continue;
			}

			len = path_len + strlen(p->d_name) + 2; 
			buf = xmalloc(len);

			if (buf) {
				struct stat statbuf;
				snprintf(buf, len, "%s/%s", path, p->d_name);

				if (!lstat(buf, &statbuf)) {
					if (statbuf.st_dev == device_id) {
						if (S_ISDIR(statbuf.st_mode)) {
							r2 = _remove_directory(buf, bytes, device_id);
						} else {
							/****** Begin Data Gathering ******/
							*bytes += statbuf.st_size;
							/****** End Data Gathering ******/
							r2 = remove(buf);
						}
					} else {
						/* device ID has changed, return error without removing */
						r2 = -1;
					}
				}

				xfree(buf);
			}
			r = r2;
		}
		closedir(d);
	}

	if (!r) {
		/****** Begin Data Gathering ******/
		struct stat sb;
		if (!lstat(path, &sb)) {
			*bytes += sb.st_size;
			r = remove(path);
		}
		/****** End Data Gathering ******/
		/* r = remove(path); */
	}

	return r;
}





