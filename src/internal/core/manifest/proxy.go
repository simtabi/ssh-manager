package manifest

import "fmt"

// ProxyCloudflared reaches a host through Cloudflare Access: ssh runs
// `cloudflared access ssh --hostname %h`, which opens the tunnel after a
// browser sign-in, so no SSH port has to be open to the internet.
const ProxyCloudflared = "cloudflared"

// ProxyKinds are the proxies sshmgr can render. raw_options may not set a
// ProxyCommand (it would run any command ssh is given), so each supported
// proxy is a field sshmgr writes itself, as it does for VM hosts.
var ProxyKinds = []string{ProxyCloudflared}

// ProxySpec routes a host's connections through a proxy command.
type ProxySpec struct {
	Kind string `json:"kind"`
}

func checkProxy(profile string, h Host) error {
	if h.Proxy == nil {
		return nil
	}
	if h.VM != nil {
		return fmt.Errorf("%s/%s: a host is either a VM or behind a proxy, not both: each renders the "+
			"one ProxyCommand ssh uses", profile, h.Alias)
	}
	for _, k := range ProxyKinds {
		if h.Proxy.Kind == k {
			return nil
		}
	}
	return fmt.Errorf("%s/%s: proxy.kind %q is not supported (supported: %s)", profile, h.Alias,
		h.Proxy.Kind, ProxyCloudflared)
}
