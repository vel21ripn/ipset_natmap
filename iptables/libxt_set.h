#ifndef _LIBXT_SET_H
#define _LIBXT_SET_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "xshared.h"

static int
get_version(unsigned *version)
{
	int res, sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);
	
	if (sockfd < 0)
		xtables_error(OTHER_PROBLEM,
			      "Can't open socket to ipset.\n");

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		xtables_error(OTHER_PROBLEM,
			      "Could not set close on exec: %s\n",
			      strerror(errno));
	}

	req_version.op = IP_SET_OP_VERSION;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req_version, &size);
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			      "Kernel module xt_set is not loaded in.\n");

	*version = req_version.version;
	
	return sockfd;
}

static void
get_set_byid(char *setname, ip_set_id_t idx)
{
	struct ip_set_req_get_set req;
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res, sockfd;

	sockfd = get_version(&req.version);
	req.op = IP_SET_OP_GET_BYINDEX;
	req.set.index = idx;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.name[0] == '\0')
		xtables_error(PARAMETER_PROBLEM,
			"Set with index %i in kernel doesn't exist.\n", idx);

	strncpy(setname, req.set.name, IPSET_MAXNAMELEN);
}

static int
get_set_byname_only(const char *setname, struct xt_set_info *info,
		    int sockfd, unsigned int version)
{
	struct ip_set_req_get_set req = { .version = version };
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res;

	req.op = IP_SET_OP_GET_BYNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);

	info->index = req.set.index;
	return req.set.index == IPSET_INVALID_ID ? 1:0;
}

static int
_get_set_byname(const char *setname, struct xt_set_info *info, int test)
{
	struct ip_set_req_get_set_family req;
	socklen_t size = sizeof(struct ip_set_req_get_set_family);
	int res, sockfd, version;

	sockfd = get_version(&req.version);
	version = req.version;
	req.op = IP_SET_OP_GET_FNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);

	if (res != 0 && errno == EBADMSG)
		/* Backward compatibility */
		return get_set_byname_only(setname, info, sockfd, version);

	close(sockfd);
	if(test) {
		if(res != 0 || size != sizeof(struct ip_set_req_get_set_family)) return 1;
		return req.set.index == IPSET_INVALID_ID ? 1:0;
	}
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set_family))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set_family),
			(size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);
	if (!(req.family == afinfo->family ||
	      req.family == NFPROTO_UNSPEC))
		xtables_error(PARAMETER_PROBLEM,
			      "The protocol family of set %s is %s, "
			      "which is not applicable.\n",
			      setname,
			      req.family == NFPROTO_IPV4 ? "IPv4" : "IPv6");

	info->index = req.set.index;
        return req.set.index == IPSET_INVALID_ID ? 1:0;
}
static void
get_set_byname(const char *setname, struct xt_set_info *info) {
        (void)_get_set_byname(setname,info,0);
}

static int
test_set_byname(const char *setname, struct xt_set_info *info) {
        return _get_set_byname(setname,info,1);
}

static void
parse_dirs_v0(const char *opt_arg, struct xt_set_info_v0 *info)
{
	char *saved = strdup(opt_arg);
	char *ptr, *tmp = saved;
	int i = 0;
	
	while (i < (IPSET_DIM_MAX - 1) && tmp != NULL) {
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->u.flags[i++] |= IPSET_SRC;
		else if (strncmp(ptr, "dst", 3) == 0)
			info->u.flags[i++] |= IPSET_DST;
		else
			xtables_error(PARAMETER_PROBLEM,
				"You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp)
		xtables_error(PARAMETER_PROBLEM,
			      "Can't be more src/dst options than %i.", 
			      IPSET_DIM_MAX);

	free(saved);
}

#if 0
static void
parse_dirs(const char *opt_arg, struct xt_set_info *info)
{
	char *saved = strdup(opt_arg);
	char *ptr, *tmp = saved;
	
	while (info->dim < IPSET_DIM_MAX && tmp != NULL) {
		info->dim++;
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->flags |= (1 << info->dim);
		else if (strncmp(ptr, "dst", 3) != 0)
			xtables_error(PARAMETER_PROBLEM,
				"You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp)
		xtables_error(PARAMETER_PROBLEM,
			      "Can't be more src/dst options than %i.", 
			      IPSET_DIM_MAX);

	free(saved);
}
#endif

#ifndef INITSETDIR
#define INITSETDIR "/etc/ipsets"
#endif

static int _auto_load(char *path,const char *setname,char *ext) {
struct stat st;
char buf[256];
int chld,fd;

if(stat(path,&st)) return 0;
if(!S_ISDIR(st.st_mode)) return 0;
snprintf(buf,sizeof(buf)-1,"%s/%s%s",path,setname,ext ? ext:"");
if(stat(buf,&st)) return 0;
if(!S_ISREG(st.st_mode)) return 0;
fd = open(buf,O_RDONLY);
if(fd < 0) return 0;

chld = fork();
signal(SIGCHLD,SIG_IGN);
if(chld < 0) return 0;
if(chld) {
	int r=0;
	close(fd);
	while(1) {
		int status;
		int p = waitpid(chld,&status,0);
		if(p < 0 && errno == EINTR) continue;
		if(p < 0) { r = 1; break; }
		r = (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 1:0;
		break;
	}
	return r;
} else {
	char *argv[]= { "ipset","restore",NULL };
	close(0);
	dup2(fd,0);
	execvp("ipset",argv);
	exit(1);
}
return 0;
}


static void try_auto_load(const char *setname)
{
char *setdir = getenv("INITSETDIR");
char *tmp,*t;
if(!setdir) {
	setdir=INITSETDIR;
}
if(!setdir) return;
tmp = strdup(setdir);
t = strtok(tmp,":");
for(; t; t = strtok(NULL,":")) {
    if(_auto_load(t,setname,"")) return;
    if(_auto_load(t,setname,".set")) return;
}
}

#endif /*_LIBXT_SET_H*/
