/*
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "dhcp_provider.h"

#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdlib.h>

typedef struct private_dhcp_provider_t private_dhcp_provider_t;

/**
 * Private data of an dhcp_provider_t object.
 */
struct private_dhcp_provider_t {

	/**
	 * Public dhcp_provider_t interface.
	 */
	dhcp_provider_t public;

	/**
	 * Completed DHCP transactions
	 */
	hashtable_t *transactions;

	/**
	 * Lock for transactions
	 */
	mutex_t *mutex;

	/**
	 * DHCP communication socket
	 */
	dhcp_socket_t *socket;

    /** 
     * Do we use per-identity or random leases (and MAC addresses)
     */
    bool identity_lease; 

    /** 
     * IPv6 prefix to search for when trying to determine the active PD 
     */
    char* ipv6_prefix;

    int ipv6_desired_pd_len;
    int ipv6_server_id;
};

/**
 * Hash ID and host to a key
 */
static uintptr_t hash_id_host(identification_t *id, host_t *host)
{
#if 0
	return chunk_hash_inc(id->get_encoding(id),
						  chunk_hash(host->get_address(host)));
#else
    return chunk_hash(id->get_encoding(id));
#endif
}

/**
 * Hash a DHCP transaction to a key, using address and id
 */
static uintptr_t hash_transaction(dhcp_transaction_t *transaction)
{
	return hash_id_host(transaction->get_identity(transaction),
						transaction->get_address(transaction));
}

/* Parse ISP prefix input. Accepts:
 *   "2a06:c701"             -> infer length from provided hextets (2 * 16 = 32)
 *   "2a06:c701/16"          -> explicit prefix length (16)
 *
 * Returns 0 on success, -1 on error.
 * Produces in6_addr isp_addr (bytes) and isp_prefix_len bits.
 */
static int parse_isp_prefix(const char *s, struct in6_addr *isp_addr, int *isp_prefix_len)
{
    if (!s || !isp_addr || !isp_prefix_len) return -1;

    char *copy = strdup(s);
    if (!copy) return -1;

    char *slash = strchr(copy, '/');
    if (slash) {
        *slash = '\0';
        char *lenstr = slash + 1;
        errno = 0;
        long v = strtol(lenstr, NULL, 10);
        if (errno || v < 0 || v > 128) { free(copy); return -1; }
        *isp_prefix_len = (int)v;
    } else {
        // infer: count non-empty hextets
        int hextets = 0;
        char *tok, *saveptr;
        for (tok = strtok_r(copy, ":", &saveptr); tok; tok = strtok_r(NULL, ":", &saveptr)) {
            if (strlen(tok) > 0) hextets++;
        }
        // hextets may be 0..8. If 0, invalid
        if (hextets <= 0) { free(copy); return -1; }
        *isp_prefix_len = hextets * 16;
    }

    // parse address with inet_pton (non-suffixed; missing groups become zeros)
    // we need the textual part (without /len)
    char *addrpart;
    if (slash) {
        // original copy now has addr part before slash
        addrpart = copy;
    } else {
        // copy was tokenized above, but we lost original; use original s up to possible '/'
        // s has no '/', so full s is address
        free(copy);
        copy = strdup(s);
        if (!copy) return -1;
        addrpart = copy;
    }

    if (inet_pton(AF_INET6, addrpart, isp_addr) != 1) {
        free(copy);
        return -1;
    }

    free(copy);
    return 0;
}

/* Build an N-bit mask into 16-byte array. nbits 0..128 */
static void build_mask_bytes(int nbits, uint8_t mask[16])
{
    memset(mask, 0, 16);
    int full = nbits / 8;
    int rem = nbits % 8;
    for (int i = 0; i < full; ++i) mask[i] = 0xFF;
    if (rem) mask[full] = (uint8_t)(0xFF << (8 - rem));
}

/* Apply mask bytes to in6 address => out */
static void apply_mask(const struct in6_addr *in, const uint8_t mask[16], struct in6_addr *out)
{
    for (int i = 0; i < 16; ++i) out->s6_addr[i] = in->s6_addr[i] & mask[i];
}

/* Count leading 1 bits in a netmask given as sockaddr_in6 netmask */
static int netmask_len_from_sockaddr(const struct sockaddr *sa)
{
    if (!sa) return -1;
    if (sa->sa_family != AF_INET6) return -1;
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
    const uint8_t *m = (const uint8_t *)(&sin6->sin6_addr);
    int bits = 0;
    for (int i = 0; i < 16; ++i) {
        uint8_t b = m[i];
        for (int bit = 7; bit >= 0; --bit) {
            if (b & (1 << bit)) bits++;
            else return bits;
        }
    }
    return bits;
}

static void format_response(struct in6_addr* pd_addr, int desired_pd_len, char *out_pd, size_t out_len)
{
    // The inet_ntop will give full expanded address like "2a06:c701:bdb6:4000::".
    // We probably want the first 4 hextets for /64 (or truncated appropriately).
    // To return without :: suffix, strip trailing "::" and zeros beyond the prefix.
    // Simplest: create an address string truncated to exactly desired_pd_len hextets.
    // Build textual form of the network by taking the network bytes and formatting only
    // the hextets that belong to desired_pd_len (each hextet = 16 bits).
    int hextets_needed = (desired_pd_len + 15) / 16; // ceil
    // uint16_t *words = (uint16_t *)&pd_addr; // note: in6_addr is big-endian bytes; assume platform compatible
    // But can't rely on endianness for uint16_t cast; build hextets manually:
    char pd_text[128];
    pd_text[0] = '\0';
    for (int i = 0; i < hextets_needed; ++i) {
        // each hextet is two bytes: bytes[2*i], bytes[2*i+1] (network order)
        uint16_t hi = (uint16_t)pd_addr->s6_addr[2*i];
        uint16_t lo = (uint16_t)pd_addr->s6_addr[2*i + 1];
        uint16_t word = (hi << 8) | lo;
        char piece[8];
        if (i == 0) snprintf(piece, sizeof(piece), "%x", word);
        else snprintf(piece, sizeof(piece), ":%x", word);
        strncat(pd_text, piece, sizeof(pd_text) - strlen(pd_text) - 1);
    }
    // success: copy to output
    strncpy(out_pd, pd_text, out_len);
    out_pd[out_len - 1] = '\0';
 }

/* main function: finds PD
 * isp_prefix: e.g. "2a06:c701" or "2a06:c701/16"
 * desired_pd_len: e.g. 64
 * out_pd: buffer to receive PD string WITHOUT /len (e.g. "2a06:c701:bdb6:4000")
 * out_len: size of out_pd
 *
 * returns 0 on success, -1 on failure
 */
int find_active_pd(const char *isp_prefix, int desired_pd_len, char *out_pd, size_t out_len)
{
    if (!isp_prefix || !out_pd || desired_pd_len <= 0 || desired_pd_len > 128) return -1;

    struct in6_addr isp_addr;
    int isp_len;
    if (parse_isp_prefix(isp_prefix, &isp_addr, &isp_len) != 0) {
        DBG1(DBG_CFG, "Invalid isp_prefix '%s'", isp_prefix);
        return -1;
    }

    // mask for comparing ISP prefix
    uint8_t isp_mask[16];
    build_mask_bytes(isp_len, isp_mask);
    struct in6_addr isp_net;
    apply_mask(&isp_addr, isp_mask, &isp_net);

    // mask for producing final PD (desired_pd_len)
    uint8_t pd_mask[16];
    build_mask_bytes(desired_pd_len, pd_mask);

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != 0) {
        DBG1(DBG_CFG, "getifaddrs failed");
        return -1;
    }

    int found = 0;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;

        // skip loopback and down interfaces as you wish; for now, accept any
        // if (!(ifa->ifa_flags & IFF_UP)) continue;  // optionally require UP

        // netmask len
        int masklen = netmask_len_from_sockaddr(ifa->ifa_netmask);
        if (masklen != desired_pd_len) continue; // we want the site PD length e.g. 64

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
        struct in6_addr addr = sin6->sin6_addr;

        // check isp prefix match
        struct in6_addr masked;
        apply_mask(&addr, isp_mask, &masked);

        // compare masked to isp_net
        if (memcmp(&masked, &isp_net, sizeof(struct in6_addr)) != 0) continue;

        // Compose PD by masking address with desired pd mask (so host bits zeroed)
        struct in6_addr pd_addr;
        apply_mask(&addr, pd_mask, &pd_addr);

        if (inet_ntop(AF_INET6, &pd_addr, out_pd, out_len) == NULL) continue; // sanity check by a system function
        //DBG1(DBG_CFG, "dhcp plugin client ipv6_prefix via inet_ntop: %s", out_pd);
        //out_pd[strlen(out_pd) - 2] = '\0'; // remove the trailing '::'
        //DBG1(DBG_CFG, "dhcp plugin client ipv6_prefix via inet_ntop without trailing colons: %s", out_pd);
        format_response(&pd_addr, desired_pd_len, out_pd, out_len);
        //DBG1(DBG_CFG, "dhcp plugin client ipv6_prefix via format_response: %s", out_pd);
        found = 1;
        break;
    }

    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_dhcp_provider_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, host_t *requested)
{
	dhcp_transaction_t *transaction, *old;
	enumerator_t *enumerator;
	identification_t *id;
	char *pool;
	host_t *vip = NULL;
    int requested_family;

	id = ike_sa->get_other_eap_id(ike_sa);
	requested_family = requested->get_family(requested);

	if (requested_family == AF_INET6)
	{
        if ( ! this->identity_lease || ! this->ipv6_prefix )
        {
            return NULL;
        }

        char active_ipv6_pd[128];
        if (find_active_pd(this->ipv6_prefix, this->ipv6_desired_pd_len, active_ipv6_pd, sizeof(active_ipv6_pd)) == 0) {
            DBG2(DBG_CFG, "dhcp plugin client identity based IPV6 assigmnents found an active PD: %s", active_ipv6_pd);
        } else {
            DBG1(DBG_CFG, "dhcp plugin client identity based IPV6 assigmnents failed to find an active PD for ipv6_prefix=%s with a desired pd len of %d", this->ipv6_prefix, this->ipv6_desired_pd_len);
            return NULL;
        }

		transaction = this->transactions->get(this->transactions, (void*)hash_id_host(id, NULL));
        if (transaction)
        {
            vip = transaction->get_address(transaction);
            if(vip)
            {
                char buf[100];
                chunk_t c = vip->get_address(vip);
                if ( this->ipv6_server_id )
                    sprintf(buf, "%s:%d:%d:%d:%d", active_ipv6_pd, this->ipv6_server_id, (int)c.ptr[1], (int)c.ptr[2], (int)c.ptr[3]);
                else
                    sprintf(buf, "%s:%d:%d:%d:%d", active_ipv6_pd, (int)c.ptr[0], (int)c.ptr[1], (int)c.ptr[2], (int)c.ptr[3]);
                return host_create_from_string_and_family(buf, AF_INET6, 0);
            }
            else
            {
                DBG1(DBG_CFG, "dhcp plugin client identity based IPV6 assigmnents failed to to find an existing ipv4 assigned IP");
            }
		}
        else
        {
            DBG1(DBG_CFG, "dhcp plugin client identity based IPV6 assigmnents failed to to find an existing ipv4 trnsaction");
        }
        return host_create_from_string_and_family("2a06:c701:bdb6:4001::7:1", AF_INET6, 0);
	} else if ( requested_family != AF_INET)
    {
        DBG1(DBG_CFG, "DHCP plugin got a request for an unknown family: %d", requested_family);
        return NULL;
    }

	//id = ike_sa->get_other_eap_id(ike_sa);
	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (!streq(pool, "dhcp"))
		{
			continue;
		}
		transaction = this->socket->enroll(this->socket, id);
		if (!transaction)
		{
			continue;
		}
		vip = transaction->get_address(transaction);
		vip = vip->clone(vip);
		this->mutex->lock(this->mutex);
		old = this->transactions->put(this->transactions,
							(void*)hash_transaction(transaction), transaction);
		this->mutex->unlock(this->mutex);
		DESTROY_IF(old);
		break;
	}
	enumerator->destroy(enumerator);
	return vip;
}

METHOD(attribute_provider_t, release_address, bool,
	private_dhcp_provider_t *this, linked_list_t *pools,
	host_t *address, ike_sa_t *ike_sa)
{
	dhcp_transaction_t *transaction;
	enumerator_t *enumerator;
	identification_t *id;
	bool found = FALSE;
	char *pool;

	if (address->get_family(address) != AF_INET)
	{
		return FALSE;
	}
	id = ike_sa->get_other_eap_id(ike_sa);
	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (!streq(pool, "dhcp"))
		{
			continue;
		}
		this->mutex->lock(this->mutex);
		transaction = this->transactions->remove(this->transactions,
										(void*)hash_id_host(id, address));
		this->mutex->unlock(this->mutex);
		if (transaction)
		{
			this->socket->release(this->socket, transaction);
			transaction->destroy(transaction);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_dhcp_provider_t *this, linked_list_t *pools, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	dhcp_transaction_t *transaction = NULL;
	enumerator_t *enumerator;
	identification_t *id;
	host_t *vip;

	if (!pools->find_first(pools, linked_list_match_str, NULL, "dhcp"))
	{
		return NULL;
	}

	id = ike_sa->get_other_eap_id(ike_sa);
	this->mutex->lock(this->mutex);
	enumerator = vips->create_enumerator(vips);
	while (enumerator->enumerate(enumerator, &vip))
	{
		transaction = this->transactions->get(this->transactions,
											  (void*)hash_id_host(id, vip));
		if (transaction)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!transaction)
	{
		this->mutex->unlock(this->mutex);
		return NULL;
	}
	return enumerator_create_cleaner(
						transaction->create_attribute_enumerator(transaction),
						(void*)this->mutex->unlock, this->mutex);
}

METHOD(dhcp_provider_t, destroy, void,
	private_dhcp_provider_t *this)
{
	enumerator_t *enumerator;
	dhcp_transaction_t *value;
	void *key;

	enumerator = this->transactions->create_enumerator(this->transactions);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		value->destroy(value);
	}
	enumerator->destroy(enumerator);
	this->transactions->destroy(this->transactions);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
dhcp_provider_t *dhcp_provider_create(dhcp_socket_t *socket)
{
	private_dhcp_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.socket = socket,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.transactions = hashtable_create(hashtable_hash_ptr,
										 hashtable_equals_ptr, 8),
	);

    this->identity_lease = lib->settings->get_bool(lib->settings,
                                "%s.plugins.dhcp.identity_lease", FALSE,
                                lib->ns);
    if (this->identity_lease)
    {
        this->ipv6_prefix = lib->settings->get_str(lib->settings, "%s.plugins.dhcp.ipv6_prefix",
                                   NULL, lib->ns);
        if (!this->ipv6_prefix)
        {
            DBG1(DBG_CFG, "dhcp plugin is set to use identity_lease but ipv6_prefix is not configured therefore ipv6 client identity based assignments will be disabled");
        }
        else
        {
            this->ipv6_desired_pd_len = lib->settings->get_int(lib->settings, "%s.plugins.dhcp.ipv6_desired_pd_len", 64, lib->ns);
            this->ipv6_server_id = lib->settings->get_int(lib->settings, "%s.plugins.dhcp.ipv6_server_ids", 0, lib->ns);
            if (this->ipv6_server_id > 9999)
            {
                DBG1(DBG_CFG, "dhcp plugin was configured with server id %d which is larger than what can be embedded in an ipv6 16 bit part when displayed as an integer. ignoring it", this->ipv6_server_id);
                this->ipv6_server_id = 0;
            }
            DBG1(DBG_CFG, "dhcp plugin is set to search for an ipv6_prefix %s with a desired pd len %d and using server id %d", this->ipv6_prefix, this->ipv6_desired_pd_len, this->ipv6_server_id);
        }
    }

	return &this->public;
}
