//go:build linux

package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	gonetURL "net/url"
	"os/user"
	"reflect"
	"strconv"
	"strings"

	bosherr "github.com/cloudfoundry/bosh-utils/errors"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	// Table and chain names are chosen for backward compatibility with existing
	// BOSH releases (e.g., pxc-release 1.1.9) that expect these specific names.
	// See docs/backward-compatible-monit-firewall.md for details.
	TableName          = "filter"
	MonitChainName     = "monit_output"
	MonitJobsChainName = "monit_output_jobs"
	NATSChainName      = "nats_output"
	MonitPort          = 2822
	AgentRuleMarker    = "bosh-agent" // UserData marker for agent-managed rules
)

// NftablesConn abstracts the nftables connection for testing
//
//counterfeiter:generate -header ./firewallfakes/linux_build_constraint.txt . NftablesConn
type NftablesConn interface {
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	InsertRule(r *nftables.Rule) *nftables.Rule
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	DelRule(r *nftables.Rule) error
	FlushChain(c *nftables.Chain)
	Flush() error
}

// DNSResolver abstracts DNS resolution for testing
//
//counterfeiter:generate -header ./firewallfakes/linux_build_constraint.txt . DNSResolver
type DNSResolver interface {
	LookupIP(host string) ([]net.IP, error)
}

// realDNSResolver uses the standard library for DNS resolution
type realDNSResolver struct{}

func (r *realDNSResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// realNftablesConn wraps the actual nftables.Conn
type realNftablesConn struct {
	conn *nftables.Conn
}

func (r *realNftablesConn) AddTable(t *nftables.Table) *nftables.Table {
	return r.conn.AddTable(t)
}

func (r *realNftablesConn) AddChain(c *nftables.Chain) *nftables.Chain {
	return r.conn.AddChain(c)
}

func (r *realNftablesConn) AddRule(rule *nftables.Rule) *nftables.Rule {
	return r.conn.AddRule(rule)
}

func (r *realNftablesConn) InsertRule(rule *nftables.Rule) *nftables.Rule {
	return r.conn.InsertRule(rule)
}

func (r *realNftablesConn) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	return r.conn.GetRules(t, c)
}

func (r *realNftablesConn) DelRule(rule *nftables.Rule) error {
	return r.conn.DelRule(rule)
}

func (r *realNftablesConn) FlushChain(c *nftables.Chain) {
	r.conn.FlushChain(c)
}

func (r *realNftablesConn) Flush() error {
	return r.conn.Flush()
}

// NftablesFirewall implements Manager and NatsFirewallHook using nftables with UID-based matching
type NftablesFirewall struct {
	conn           NftablesConn
	resolver       DNSResolver
	logger         boshlog.Logger
	logTag         string
	options        Options
	table          *nftables.Table
	monitChain     *nftables.Chain
	monitJobsChain *nftables.Chain
	natsChain      *nftables.Chain
}

// NewNftablesFirewall creates a new nftables-based firewall manager
func NewNftablesFirewall(logger boshlog.Logger, options Options) (Manager, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, bosherr.WrapError(err, "Creating nftables connection")
	}

	return NewNftablesFirewallWithDeps(
		&realNftablesConn{conn: conn},
		&realDNSResolver{},
		logger,
		options,
	), nil
}

// NewNftablesFirewallWithDeps creates a firewall manager with injected dependencies (for testing)
func NewNftablesFirewallWithDeps(conn NftablesConn, resolver DNSResolver, logger boshlog.Logger, options Options) Manager {
	return &NftablesFirewall{
		conn:     conn,
		resolver: resolver,
		logger:   logger,
		logTag:   "NftablesFirewall",
		options:  options,
	}
}

// SetupMonitFirewall creates firewall rules to protect monit (port 2822).
// Only root (UID 0) is allowed to connect by default.
// Jobs can add their own access rules to the monit_output_jobs chain or
// insert rules directly into monit_output chain (for backward compatibility).
//
// Architecture:
//   - monit_output_jobs: Regular chain for job-managed rules (never flushed by agent)
//   - monit_output: Base chain with hook that jumps to jobs chain, then applies agent rules
//
// This implementation uses a declarative state converger that:
//  1. Compares current rules against desired state
//  2. Only modifies agent-managed rules (identified by UserData marker)
//  3. Preserves rules inserted by jobs (e.g., pxc-release galera-agent)
func (f *NftablesFirewall) SetupMonitFirewall() error {
	f.logger.Info(f.logTag, "Setting up monit firewall rules (UID-based matching)")

	// Create or get our table
	f.ensureTable()

	// Create jobs chain if it doesn't exist (never flush it - job rules persist)
	f.ensureMonitJobsChain()

	// Create monit chain
	f.ensureMonitChain()

	// Converge to desired state (preserves job-inserted rules)
	if err := f.convergeMonitRules(); err != nil {
		return bosherr.WrapError(err, "Converging monit rules")
	}

	// Commit all changes
	if err := f.conn.Flush(); err != nil {
		return bosherr.WrapError(err, "Flushing nftables rules")
	}

	f.logger.Info(f.logTag, "Successfully set up monit firewall rules")
	return nil
}

// SetupNATSFirewall creates firewall rules to protect NATS.
// This resolves DNS and should be called before each connection attempt.
func (f *NftablesFirewall) SetupNATSFirewall(mbusURL string) error {
	// Parse URL to get host and port
	host, port, err := parseNATSURL(mbusURL)
	if err != nil {
		// Not an error for https URLs or empty URLs (create-env case)
		f.logger.Info(f.logTag, "Skipping NATS firewall: %s", err)
		return nil
	}

	// Resolve host to IP addresses
	var addrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IP{ip}
	} else {
		addrs, err = f.resolver.LookupIP(host)
		if err != nil {
			f.logger.Warn(f.logTag, "DNS resolution failed for %s: %s", host, err)
			return nil
		}
	}

	f.logger.Debug(f.logTag, "Setting up NATS firewall for %s:%d (resolved to %v)", host, port, addrs)

	// Ensure table exists
	f.ensureTable()

	// Ensure NATS chain exists
	f.ensureNATSChain()

	// Flush NATS chain (removes old rules for previous IPs)
	f.conn.FlushChain(f.natsChain)

	// Add rules for each resolved IP
	for _, addr := range addrs {
		f.addNATSAllowRule(addr, port)
		f.addNATSBlockRule(addr, port)
	}

	// Commit
	if err := f.conn.Flush(); err != nil {
		return bosherr.WrapError(err, "Flushing nftables rules")
	}

	f.logger.Info(f.logTag, "Updated NATS firewall rules for %s:%d", host, port)
	return nil
}

// BeforeConnect implements NatsFirewallHook. Called before each NATS connection attempt.
func (f *NftablesFirewall) BeforeConnect(mbusURL string) error {
	return f.SetupNATSFirewall(mbusURL)
}

func (f *NftablesFirewall) ensureTable() {
	f.table = &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   TableName,
	}
	f.conn.AddTable(f.table)
}

func (f *NftablesFirewall) ensureMonitChain() {
	priority := nftables.ChainPriority(*nftables.ChainPriorityFilter - 1)

	f.monitChain = &nftables.Chain{
		Name:     MonitChainName,
		Table:    f.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: &priority,
		Policy:   policyPtr(nftables.ChainPolicyAccept),
	}
	f.conn.AddChain(f.monitChain)
}

// ensureMonitJobsChain creates a regular chain (no hook) for job-managed rules.
// This chain is never flushed by the agent, allowing job rules to persist across agent restarts.
// Jobs can add rules to this chain via pre-start scripts using the nft CLI or bosh-monit-access helper.
func (f *NftablesFirewall) ensureMonitJobsChain() {
	f.monitJobsChain = &nftables.Chain{
		Name:  MonitJobsChainName,
		Table: f.table,
		// No Type, Hooknum, Priority, or Policy - this is a regular chain
		// that can only be reached via jump from monit_output
	}
	f.conn.AddChain(f.monitJobsChain)
}

func (f *NftablesFirewall) ensureNATSChain() {
	priority := nftables.ChainPriority(*nftables.ChainPriorityFilter - 1)

	f.natsChain = &nftables.Chain{
		Name:     NATSChainName,
		Table:    f.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: &priority,
		Policy:   policyPtr(nftables.ChainPolicyAccept),
	}
	f.conn.AddChain(f.natsChain)
}

// desiredRule represents a rule that the agent wants to have in the chain
type desiredRule struct {
	exprs    []expr.Any
	position string // "first" (insert at beginning) or "last" (append at end)
}

// convergeMonitRules implements a declarative state converger that:
// 1. Gets current rules in the chain
// 2. Identifies agent-managed rules (by UserData marker)
// 3. Compares against desired state
// 4. Only adds/removes rules as needed, preserving job-inserted rules
func (f *NftablesFirewall) convergeMonitRules() error {
	// Get current rules in chain
	currentRules, err := f.conn.GetRules(f.table, f.monitChain)
	if err != nil {
		// Chain might not exist yet or be empty, treat as empty
		f.logger.Debug(f.logTag, "Could not get current rules (chain may be new): %s", err)
		currentRules = []*nftables.Rule{}
	}

	// Build desired state
	desired, err := f.buildDesiredMonitRules()
	if err != nil {
		return err
	}

	// Separate agent rules from job rules
	var agentRules []*nftables.Rule
	for _, r := range currentRules {
		if isAgentRule(r) {
			agentRules = append(agentRules, r)
		}
	}

	// Check if current agent rules match desired state (quick path)
	if f.agentRulesMatchDesired(agentRules, desired) {
		f.logger.Debug(f.logTag, "Monit rules already in desired state, no changes needed")
		return nil
	}

	f.logger.Debug(f.logTag, "Monit rules need updating, converging to desired state")

	// Delete all existing agent rules (they will be recreated)
	for _, r := range agentRules {
		if err := f.conn.DelRule(r); err != nil {
			f.logger.Warn(f.logTag, "Failed to delete agent rule (handle %d): %s", r.Handle, err)
		}
	}

	// Add desired rules in correct order
	// Process "first" rules in reverse order (since InsertRule prepends)
	// Then process "last" rules in order (since AddRule appends)
	var firstRules, lastRules []desiredRule
	for _, d := range desired {
		if d.position == "first" {
			firstRules = append(firstRules, d)
		} else {
			lastRules = append(lastRules, d)
		}
	}

	// Insert "first" rules in reverse order so they end up in correct order
	for i := len(firstRules) - 1; i >= 0; i-- {
		f.insertMarkedRule(firstRules[i].exprs)
	}

	// Append "last" rules in order
	for _, d := range lastRules {
		f.addMarkedRule(d.exprs)
	}

	return nil
}

// buildDesiredMonitRules returns the desired state of agent-managed rules
// The order is:
//  1. Jump to monit_output_jobs chain (so job rules are checked first)
//  2. Allow UID 0 (root) access
//  3. Allow vcap UID access (if AllowVcapMonitAccess is enabled)
//  4. Drop all other access (at end)
func (f *NftablesFirewall) buildDesiredMonitRules() ([]desiredRule, error) {
	rules := []desiredRule{
		{
			exprs:    f.buildJumpToJobsChainExprs(),
			position: "first",
		},
		{
			exprs:    f.buildMonitAllowExprs(0), // root UID
			position: "first",
		},
	}

	// Add vcap allow rule if configured
	if f.options.AllowVcapMonitAccess {
		vcapUID, err := lookupUID("vcap")
		if err != nil {
			return nil, bosherr.WrapError(err, "Looking up vcap user for monit firewall")
		}
		f.logger.Info(f.logTag, "Allowing vcap user (UID %d) access to monit", vcapUID)
		rules = append(rules, desiredRule{
			exprs:    f.buildMonitAllowExprs(vcapUID),
			position: "first",
		})
	}

	// Drop rule always goes last
	rules = append(rules, desiredRule{
		exprs:    f.buildMonitBlockExprs(),
		position: "last",
	})

	return rules, nil
}

// buildJumpToJobsChainExprs creates expressions for jumping to the jobs chain
func (f *NftablesFirewall) buildJumpToJobsChainExprs() []expr.Any {
	return []expr.Any{
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: MonitJobsChainName,
		},
	}
}

// buildMonitAllowExprs creates expressions for allowing a specific UID access to monit
func (f *NftablesFirewall) buildMonitAllowExprs(uid uint32) []expr.Any {
	exprs := f.buildUIDMatchExprs(uid)
	exprs = append(exprs, f.buildLoopbackDestExprs()...)
	exprs = append(exprs, f.buildTCPDestPortExprs(MonitPort)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	return exprs
}

// buildMonitBlockExprs creates expressions for blocking all other access to monit
func (f *NftablesFirewall) buildMonitBlockExprs() []expr.Any {
	exprs := f.buildLoopbackDestExprs()
	exprs = append(exprs, f.buildTCPDestPortExprs(MonitPort)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	return exprs
}

// isAgentRule checks if a rule was created by the bosh-agent
func isAgentRule(r *nftables.Rule) bool {
	return string(r.UserData) == AgentRuleMarker
}

// agentRulesMatchDesired checks if current agent rules match the desired state
func (f *NftablesFirewall) agentRulesMatchDesired(agentRules []*nftables.Rule, desired []desiredRule) bool {
	if len(agentRules) != len(desired) {
		return false
	}

	// Check that all desired rules exist in current agent rules
	for _, d := range desired {
		found := false
		for _, r := range agentRules {
			if f.exprsEqual(r.Exprs, d.exprs) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// exprsEqual compares two expression slices for equality
func (f *NftablesFirewall) exprsEqual(a, b []expr.Any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// insertMarkedRule inserts a rule at the beginning of the chain with agent marker
func (f *NftablesFirewall) insertMarkedRule(exprs []expr.Any) {
	f.conn.InsertRule(&nftables.Rule{
		Table:    f.table,
		Chain:    f.monitChain,
		Exprs:    exprs,
		UserData: []byte(AgentRuleMarker),
	})
}

// addMarkedRule appends a rule at the end of the chain with agent marker
func (f *NftablesFirewall) addMarkedRule(exprs []expr.Any) {
	f.conn.AddRule(&nftables.Rule{
		Table:    f.table,
		Chain:    f.monitChain,
		Exprs:    exprs,
		UserData: []byte(AgentRuleMarker),
	})
}

func (f *NftablesFirewall) addNATSAllowRule(addr net.IP, port int) {
	// Rule: meta skuid 0 ip daddr <addr> tcp dport <port> accept
	exprs := f.buildUIDMatchExprs(0)
	exprs = append(exprs, f.buildDestIPExprs(addr)...)
	exprs = append(exprs, f.buildTCPDestPortExprs(port)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	f.conn.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.natsChain,
		Exprs: exprs,
	})
}

func (f *NftablesFirewall) addNATSBlockRule(addr net.IP, port int) {
	// Rule: ip daddr <addr> tcp dport <port> drop
	exprs := f.buildDestIPExprs(addr)
	exprs = append(exprs, f.buildTCPDestPortExprs(port)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})

	f.conn.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.natsChain,
		Exprs: exprs,
	})
}

// buildUIDMatchExprs creates expressions for matching socket UID
func (f *NftablesFirewall) buildUIDMatchExprs(uid uint32) []expr.Any {
	uidBytes := make([]byte, 4)
	binary.NativeEndian.PutUint32(uidBytes, uid)

	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeySKUID,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     uidBytes,
		},
	}
}

// buildLoopbackDestExprs creates expressions for matching IPv4 loopback destination.
// Note: IPv6 loopback (::1) is intentionally not protected because monit only
// binds to 127.0.0.1:2822 (see jobsupervisor/monit/provider.go).
func (f *NftablesFirewall) buildLoopbackDestExprs() []expr.Any {
	return []expr.Any{
		// Check this is IPv4
		&expr.Meta{
			Key:      expr.MetaKeyNFPROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.NFPROTO_IPV4},
		},
		// Load destination IP
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16, // Destination IP offset in IPv4 header
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     net.ParseIP("127.0.0.1").To4(),
		},
	}
}

func (f *NftablesFirewall) buildDestIPExprs(ip net.IP) []expr.Any {
	if ip4 := ip.To4(); ip4 != nil {
		return []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.NFPROTO_IPV4},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip4,
			},
		}
	}

	// IPv6
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyNFPROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.NFPROTO_IPV6},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       24, // Destination IP offset in IPv6 header
			Len:          16,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ip.To16(),
		},
	}
}

func (f *NftablesFirewall) buildTCPDestPortExprs(port int) []expr.Any {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // Destination port offset in TCP header
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		},
	}
}

func policyPtr(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}

func parseNATSURL(mbusURL string) (string, int, error) {
	if mbusURL == "" || strings.HasPrefix(mbusURL, "https://") {
		return "", 0, fmt.Errorf("skipping URL: %s", mbusURL)
	}

	u, err := gonetURL.Parse(mbusURL)
	if err != nil {
		return "", 0, err
	}

	if u.Hostname() == "" {
		return "", 0, fmt.Errorf("empty hostname in URL")
	}

	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Hostname()
		portStr = "4222"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parsing port: %w", err)
	}

	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of valid range (1-65535)", port)
	}

	return host, port, nil
}

// lookupUID looks up a user by name and returns their UID as uint32
func lookupUID(username string) (uint32, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing UID for user %s: %w", username, err)
	}
	return uint32(uid), nil
}
