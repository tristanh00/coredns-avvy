package avvy

import (
	"strings"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/ethereum/go-ethereum/ethclient"
	avvy "github.com/avvydomains/golang-client"
)

func init() {
	caddy.RegisterPlugin("avvy", caddy.Plugin{
		ServerType: "dns",
		Action:     setupAvvy,
	})
}

func setupAvvy(c *caddy.Controller) error {
	connection, ipfsGatewayAs, ipfsGatewayAAAAs, err := avvyParse(c)
	if err != nil {
		return plugin.Error("avvy", err)
	}

	client, err := ethclient.Dial(connection)
	if err != nil {
		return plugin.Error("avvy", err)
	}

	// Obtain the registry contract
	registry, err := avvy.NewRegistry(client)
	if err != nil {
		return plugin.Error("avvy", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Avvy{
			Next:               next,
			Client:             client,
			Registry:           registry,
			IPFSGatewayAs:      ipfsGatewayAs,
			IPFSGatewayAAAAs:   ipfsGatewayAAAAs,
		}
	})

	return nil
}

func avvyParse(c *caddy.Controller) (string, []string, []string, []string, error) {
	var connection string
	ipfsGatewayAs := make([]string, 0)
	ipfsGatewayAAAAs := make([]string, 0)

	c.Next()
	for c.NextBlock() {
		switch strings.ToLower(c.Val()) {
		case "connection":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid connection; no value")
			}
			if len(args) > 1 {
				return "", nil, nil, nil, c.Errf("invalid connection; multiple values")
			}
			connection = args[0]
		case "ipfsgatewaya":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid IPFS gateway A; no value")
			}
			ipfsGatewayAs = make([]string, len(args))
			copy(ipfsGatewayAs, args)
		case "ipfsgatewayaaaa":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid IPFS gateway AAAA; no value")
			}
			ipfsGatewayAAAAs = make([]string, len(args))
			copy(ipfsGatewayAAAAs, args)
		default:
			return "", nil, nil, nil, c.Errf("unknown value %v", c.Val())
		}
	}
	if connection == "" {
		return "", nil, nil, nil, c.Errf("no connection")
	}
	return connection, ipfsGatewayAs, ipfsGatewayAAAAs, nil
}
