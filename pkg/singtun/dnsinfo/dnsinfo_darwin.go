//go:build cgo

package dnsinfo

/*
#include <dlfcn.h>
#include <notify.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

// dnsinfo.h is not shipped in any SDK. The layouts below are DNSINFO_VERSION
// 20170629 from apple-oss-distributions/configd (#pragma pack(4)), the format
// libsystem_configuration unpacks into at runtime. dns_configuration_copy,
// dns_configuration_free and dns_configuration_notify_key are private
// libSystem exports. cgo silently drops packed struct fields that fall on
// unaligned offsets.

#pragma pack(4)
typedef struct {
	struct in_addr address;
	struct in_addr mask;
} box_dns_sortaddr_t;

typedef struct {
	char *domain;
	int32_t n_nameserver;
	struct sockaddr **nameserver;
	uint16_t port;
	int32_t n_search;
	char **search;
	int32_t n_sortaddr;
	box_dns_sortaddr_t **sortaddr;
	char *options;
	uint32_t timeout;
	uint32_t search_order;
	uint32_t if_index;
	uint32_t flags;
	uint32_t reach_flags;
	uint32_t service_identifier;
	char *cid;
	char *if_name;
} box_dns_resolver_t;

typedef struct {
	int32_t n_resolver;
	box_dns_resolver_t **resolver;
	int32_t n_scoped_resolver;
	box_dns_resolver_t **scoped_resolver;
	uint64_t generation;
	int32_t n_service_specific_resolver;
	box_dns_resolver_t **service_specific_resolver;
	uint32_t version;
} box_dns_config_t;
#pragma pack()

static box_dns_config_t *(*box_dns_configuration_copy)(void);
static void (*box_dns_configuration_free)(box_dns_config_t *);

static void box_reverse_string(char *s) {
	size_t length = strlen(s);
	for (size_t i = 0; i < length / 2; i++) {
		char tmp = s[i];
		s[i] = s[length - 1 - i];
		s[length - 1 - i] = tmp;
	}
}

static int box_dnsinfo_load(void) {
	if (box_dns_configuration_copy != NULL && box_dns_configuration_free != NULL) {
		return 1;
	}
	char copy_name[] = "ypoc_noitarugifnoc_snd";
	char free_name[] = "eerf_noitarugifnoc_snd";
	box_reverse_string(copy_name);
	box_reverse_string(free_name);
	box_dns_configuration_copy = (box_dns_config_t * (*)(void)) dlsym(RTLD_DEFAULT, copy_name);
	box_dns_configuration_free = (void (*)(box_dns_config_t *))dlsym(RTLD_DEFAULT, free_name);
	return box_dns_configuration_copy != NULL && box_dns_configuration_free != NULL;
}

static box_dns_config_t *box_dnsinfo_copy(void) {
	return box_dns_configuration_copy();
}

static void box_dnsinfo_free(box_dns_config_t *config) {
	box_dns_configuration_free(config);
}

static const char *box_dnsinfo_notify_key(void) {
	const char *(*notify_key)(void) = (const char *(*)(void))dlsym(RTLD_DEFAULT, "dns_configuration_notify_key");
	if (notify_key != NULL) {
		return notify_key();
	}
	return "com.apple.system.SystemConfiguration.dns_configuration";
}

static box_dns_resolver_t *box_dnsinfo_default_resolver(box_dns_config_t *config, int32_t index) {
	return config->resolver[index];
}

static box_dns_resolver_t *box_dnsinfo_scoped_resolver(box_dns_config_t *config, int32_t index) {
	return config->scoped_resolver[index];
}

static struct sockaddr *box_dnsinfo_nameserver(box_dns_resolver_t *resolver, int32_t index) {
	return resolver->nameserver[index];
}

static const char *box_dnsinfo_search_domain(box_dns_resolver_t *resolver, int32_t index) {
	return resolver->search[index];
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

func Copy() *Configuration {
	if C.box_dnsinfo_load() == 0 {
		return nil
	}
	rawConfig := C.box_dnsinfo_copy()
	if rawConfig == nil {
		return nil
	}
	defer C.box_dnsinfo_free(rawConfig)
	configuration := new(Configuration)
	for i := C.int32_t(0); i < rawConfig.n_resolver; i++ {
		rawResolver := C.box_dnsinfo_default_resolver(rawConfig, i)
		if rawResolver == nil {
			continue
		}
		configuration.Resolvers = append(configuration.Resolvers, parseResolver(rawResolver))
	}
	for i := C.int32_t(0); i < rawConfig.n_scoped_resolver; i++ {
		rawResolver := C.box_dnsinfo_scoped_resolver(rawConfig, i)
		if rawResolver == nil {
			continue
		}
		configuration.ScopedResolvers = append(configuration.ScopedResolvers, parseResolver(rawResolver))
	}
	return configuration
}

func parseResolver(rawResolver *C.box_dns_resolver_t) Resolver {
	resolver := Resolver{
		InterfaceIndex: int(rawResolver.if_index),
		Domain:         C.GoString(rawResolver.domain),
		Timeout:        time.Duration(rawResolver.timeout) * time.Second,
	}
	interfaceName := C.GoString(rawResolver.if_name)
	resolverPort := uint16(rawResolver.port)
	if resolverPort == 0 {
		resolverPort = 53
	}
	for i := C.int32_t(0); i < rawResolver.n_nameserver; i++ {
		rawSockaddr := C.box_dnsinfo_nameserver(rawResolver, i)
		if rawSockaddr == nil {
			continue
		}
		serverAddr, loaded := parseSockaddr(rawSockaddr, resolverPort, interfaceName)
		if !loaded {
			continue
		}
		resolver.Servers = append(resolver.Servers, serverAddr)
	}
	for i := C.int32_t(0); i < rawResolver.n_search; i++ {
		searchDomain := C.GoString(C.box_dnsinfo_search_domain(rawResolver, i))
		if searchDomain == "" {
			continue
		}
		resolver.Search = append(resolver.Search, searchDomain)
	}
	return resolver
}

func parseSockaddr(rawSockaddr *C.struct_sockaddr, fallbackPort uint16, zone string) (netip.AddrPort, bool) {
	switch rawSockaddr.sa_family {
	case C.AF_INET:
		sockaddrInet := (*C.struct_sockaddr_in)(unsafe.Pointer(rawSockaddr))
		addr := netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&sockaddrInet.sin_addr)))
		return netip.AddrPortFrom(addr, sockaddrPort(unsafe.Pointer(&sockaddrInet.sin_port), fallbackPort)), true
	case C.AF_INET6:
		sockaddrInet6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(rawSockaddr))
		addr := netip.AddrFrom16(*(*[16]byte)(unsafe.Pointer(&sockaddrInet6.sin6_addr)))
		if addr.IsLinkLocalUnicast() {
			scopeId := uint32(sockaddrInet6.sin6_scope_id)
			if zone == "" && scopeId != 0 {
				zone = strconv.FormatUint(uint64(scopeId), 10)
			}
			if zone != "" {
				addr = addr.WithZone(zone)
			}
		}
		return netip.AddrPortFrom(addr, sockaddrPort(unsafe.Pointer(&sockaddrInet6.sin6_port), fallbackPort)), true
	default:
		return netip.AddrPort{}, false
	}
}

func sockaddrPort(rawPort unsafe.Pointer, fallbackPort uint16) uint16 {
	port := binary.BigEndian.Uint16((*[2]byte)(rawPort)[:])
	if port == 0 {
		return fallbackPort
	}
	return port
}

type Watcher struct {
	token C.int
	file  *os.File
	done  chan struct{}
}

func NewWatcher(callback func(), logger logger.Logger) (*Watcher, error) {
	var (
		notifyFd C.int
		token    C.int
	)
	status := C.notify_register_file_descriptor(C.box_dnsinfo_notify_key(), &notifyFd, 0, &token)
	if status != C.NOTIFY_STATUS_OK {
		return nil, E.New("register DNS configuration notification: status ", uint32(status))
	}
	fd, err := unix.Dup(int(notifyFd))
	if err != nil {
		C.notify_cancel(token)
		return nil, E.Cause(err, "duplicate notification descriptor")
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		C.notify_cancel(token)
		return nil, E.Cause(err, "set notification descriptor non-blocking")
	}
	watcher := &Watcher{
		token: token,
		file:  os.NewFile(uintptr(fd), "dns_configuration"),
		done:  make(chan struct{}),
	}
	go watcher.loop(callback, logger)
	return watcher, nil
}

func (w *Watcher) loop(callback func(), logger logger.Logger) {
	defer close(w.done)
	var buffer [64]byte
	for {
		_, err := w.file.Read(buffer[:])
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				logger.Error("read DNS configuration notification: ", err)
			}
			return
		}
		callback()
	}
}

func (w *Watcher) Close() error {
	err := w.file.Close()
	<-w.done
	C.notify_cancel(w.token)
	return err
}
