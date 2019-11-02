#ifndef _EBT_DSET_H
#define _EBT_DSET_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

static int
get_version(unsigned *version)
{
	int res, sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	struct domain_set_req_version req_version;
	socklen_t size = sizeof(req_version);
	
	if (sockfd < 0)
		ebt_print_error2(
			      "Can't open socket to dset.\n");

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		ebt_print_error2(
			      "Could not set close on exec: %s\n",
			      strerror(errno));
	}

	req_version.op = DOMAIN_SET_OP_VERSION;
	res = getsockopt(sockfd, SOL_IP, SO_DOMAIN_SET, &req_version, &size);
	if (res != 0)
		ebt_print_error2(
			      "Kernel module xt_set is not loaded in.\n");

	*version = req_version.version;
	
	return sockfd;
}

static void
get_set_byid(char *setname, domain_set_id_t idx)
{
	struct domain_set_req_get_set req;
	socklen_t size = sizeof(struct domain_set_req_get_set);
	int res, sockfd;

	sockfd = get_version(&req.version);
	req.op = DOMAIN_SET_OP_GET_BYINDEX;
	req.set.index = idx;
	res = getsockopt(sockfd, SOL_IP, SO_DOMAIN_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		ebt_print_error2(
			"Problem when communicating with dset, errno=%d.\n",
			errno);
	if (size != sizeof(struct domain_set_req_get_set))
		ebt_print_error2(
			"Incorrect return size from kernel duriipng dset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct domain_set_req_get_set), (size_t)size);
	if (req.set.name[0] == '\0')
		ebt_print_error2(
			"Set with index %i in kernel doesn't exist.\n", idx);

	strncpy(setname, req.set.name, DSET_MAXNAMELEN);
}

static void
get_set_byname_only(const char *setname, struct xt_dset_info *info,
		    int sockfd, unsigned int version)
{
	struct domain_set_req_get_set req = { .version = version };
	socklen_t size = sizeof(struct domain_set_req_get_set);
	int res;

	req.op = DOMAIN_SET_OP_GET_BYNAME;
	strncpy(req.set.name, setname, DSET_MAXNAMELEN);
	req.set.name[DSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_DOMAIN_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		ebt_print_error2(
			"Problem when communicating with dset, errno=%d.\n",
			errno);
	if (size != sizeof(struct domain_set_req_get_set))
		ebt_print_error2(
			"Incorrect return size from kernel during dset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct domain_set_req_get_set), (size_t)size);
	if (req.set.index == DSET_INVALID_ID)
		ebt_print_error2(
			      "Set %s doesn't exist.\n", setname);

	info->index = req.set.index;
}

static void
get_set_byname(const char *setname, struct xt_dset_info *info)
{
	struct domain_set_req_get_set_family req;
	socklen_t size = sizeof(struct domain_set_req_get_set_family);
	int res, sockfd, version;

	sockfd = get_version(&req.version);
	version = req.version;
	req.op = DOMAIN_SET_OP_GET_FNAME;
	strncpy(req.set.name, setname, DSET_MAXNAMELEN);
	req.set.name[DSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_DOMAIN_SET, &req, &size);

	if (res != 0 && errno == EBADMSG)
		/* Backward compatibility */
		return get_set_byname_only(setname, info, sockfd, version);

	close(sockfd);
	if (res != 0)
		ebt_print_error2(
			"Problem when communicating with dset, errno=%d.\n",
			errno);
	if (size != sizeof(struct domain_set_req_get_set_family))
		ebt_print_error2(
			"Incorrect return size from kernel during dset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct domain_set_req_get_set_family),
			(size_t)size);
	if (req.set.index == DSET_INVALID_ID)
		ebt_print_error2(
			      "Set %s doesn't exist.\n", setname);
	if (!(req.family == NFPROTO_IPV4 || //modify
	      req.family == NFPROTO_UNSPEC))
		ebt_print_error2(
			      "The protocol family of set %s is %s, "
			      "which is not applicable.\n",
			      setname,
			      req.family == NFPROTO_IPV4 ? "IPv4" : "IPv6");

	info->index = req.set.index;
}

#endif /*_EBT_DSET_H*/
