# Proposal: Backward-Compatible Monit Firewall

## Problem Statement

The current bosh-agent PR #399 implements UID-based nftables firewall protection for monit (port 2822) and NATS connections. However, the chosen table and chain names are incompatible with existing BOSH releases like pxc-release 1.1.9, which expect a specific nftables structure.

### Current pxc-release 1.1.9 Behavior

The galera-agent job in pxc-release 1.1.9 contains this logic in `service.bash`:

```bash
if type -f -p nft >/dev/null && nft list ruleset | grep -q monit_output; then
  rule_handle=$(nft -a list ruleset | awk '/galera-agent/ { print $NF }')
  if [[ -n $rule_handle ]]; then
    nft delete rule inet filter monit_output handle "${rule_handle}"
  fi
  nft insert rule inet filter monit_output index 2 \
    socket cgroupv2 level 2 "system.slice/runc-bpm-galera-agent.scope" \
    ip daddr 127.0.0.1 tcp dport 2822 \
    log prefix '"Matched cgroup galera-agent monit access rule: "' \
    accept
fi
```

This expects:
1. **Chain name**: `monit_output` (detected via `grep -q monit_output`)
2. **Table**: `inet filter` (the default filter table)
3. **Rule insertion at index 2**: After the first two rules, before the drop rule

### Current PR #399 Structure

```
table inet bosh_agent {
    chain monit_access_jobs { }
    chain monit_access {
        type filter hook output priority filter - 1; policy accept;
        jump monit_access_jobs
        meta skuid 0 ip daddr 127.0.0.1 tcp dport 2822 accept
        ip daddr 127.0.0.1 tcp dport 2822 drop
    }
    chain nats_access { ... }
}
```

This uses:
- Table `bosh_agent` (not `filter`)
- Chain `monit_access` (not `monit_output`)

As a result, pxc-release 1.1.9's `grep -q monit_output` fails, no firewall rule is added, and galera-agent (running as vcap/UID 1000) cannot access monit.

## Proposed Solution

Modify the bosh-agent firewall to use backward-compatible table and chain names while maintaining the same security properties.

### Proposed Structure

```
table inet filter {
    chain monit_output_jobs { }      # Regular chain for job-managed rules
    chain monit_output {             # Base chain with output hook
        type filter hook output priority filter - 1; policy accept;
        jump monit_output_jobs       # Index 0: Check job rules first
        meta skuid 0 ip daddr 127.0.0.1 tcp dport 2822 accept  # Index 1: Allow root
        ip daddr 127.0.0.1 tcp dport 2822 drop                  # Index 2: Drop others
    }
    chain nats_output {              # NATS protection
        type filter hook output priority filter - 1; policy accept;
        meta skuid 0 ip daddr <nats_ip> tcp dport <port> accept
        ip daddr <nats_ip> tcp dport <port> drop
    }
}
```

### How This Achieves Backward Compatibility

1. **pxc 1.1.9 detection works**: `grep -q monit_output` finds the chain
2. **Rule insertion works**: `insert rule inet filter monit_output index 2` inserts the cgroup rule after the UID 0 accept rule but before the drop rule:
   ```
   chain monit_output {
       jump monit_output_jobs                    # Index 0
       meta skuid 0 ... accept                   # Index 1
       socket cgroupv2 ... accept                # Index 2 (inserted by pxc 1.1.9)
       ip daddr 127.0.0.1 tcp dport 2822 drop    # Index 3 (pushed down)
   }
   ```
3. **Cgroup matching works**: Verified that `socket cgroupv2 level 2 "system.slice/runc-bpm-galera-agent.scope"` rules can be created on noble stemcells
4. **Future releases** can use `monit_output_jobs` chain for the new mechanism

### Naming Changes

| Current (PR #399) | Proposed | Reason |
|-------------------|----------|--------|
| Table: `bosh_agent` | Table: `filter` | pxc 1.1.9 expects `inet filter` |
| Chain: `monit_access` | Chain: `monit_output` | pxc 1.1.9 greps for `monit_output` |
| Chain: `monit_access_jobs` | Chain: `monit_output_jobs` | Consistency with base chain name |
| Chain: `nats_access` | Chain: `nats_output` | Consistency (optional) |

### Code Changes Required

In `platform/firewall/nftables_firewall.go`:

```go
const (
    // Changed for backward compatibility with existing BOSH releases
    TableName          = "filter"           // Was: "bosh_agent"
    MonitChainName     = "monit_output"     // Was: "monit_access"
    MonitJobsChainName = "monit_output_jobs" // Was: "monit_access_jobs"
    NATSChainName      = "nats_output"      // Was: "nats_access"
)
```

## Verification

Tested on noble stemcell 1.215-custom with pxc-release 1.1.9:

1. **Cgroup path exists**: `/sys/fs/cgroup/system.slice/runc-bpm-galera-agent.scope`
2. **Cgroup rule creation succeeds**:
   ```bash
   nft add rule inet filter monit_output \
     socket cgroupv2 level 2 "system.slice/runc-bpm-galera-agent.scope" \
     ip daddr 127.0.0.1 tcp dport 2822 accept
   # Exit code: 0
   ```
3. **Rule insertion at index 2 works correctly**: New rule is placed before the drop rule

## Impact on Future Releases

The `bosh-monit-access` helper (not yet merged) would need to be updated to look for:
- Table: `inet filter` (instead of `inet bosh_agent`)
- Chain: `monit_output_jobs` (instead of `monit_access_jobs`)

Since this helper is not yet released, this is a minor adjustment.

## Tradeoffs

| Pros | Cons |
|------|------|
| Full backward compatibility with pxc 1.1.9 and similar releases | Uses default `filter` table instead of isolated `bosh_agent` table |
| No changes required in existing BOSH releases | Slightly less namespace isolation |
| Single stemcell works for all release versions | Chain names less clearly indicate ownership |
| Cgroup-based rules continue to work | |

## Conclusion

By using the `inet filter` table with `monit_output` chain naming, we maintain full backward compatibility with existing BOSH releases while preserving the security benefits of the UID-based firewall. The tradeoff of reduced namespace isolation is acceptable given the operational benefits of not requiring coordinated updates across multiple releases.
