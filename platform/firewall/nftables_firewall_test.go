//go:build linux

package firewall_test

import (
	"errors"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/cloudfoundry/bosh-agent/v2/platform/firewall"
	"github.com/cloudfoundry/bosh-agent/v2/platform/firewall/firewallfakes"
)

var _ = Describe("NftablesFirewall", func() {
	var (
		fakeConn     *firewallfakes.FakeNftablesConn
		fakeResolver *firewallfakes.FakeDNSResolver
		logger       boshlog.Logger
		manager      firewall.Manager
	)

	BeforeEach(func() {
		fakeConn = &firewallfakes.FakeNftablesConn{}
		fakeResolver = &firewallfakes.FakeDNSResolver{}
		logger = boshlog.NewWriterLogger(boshlog.LevelDebug, GinkgoWriter)
		manager = firewall.NewNftablesFirewallWithDeps(fakeConn, fakeResolver, logger)

		// Default: GetRules returns empty (no existing rules)
		fakeConn.GetRulesReturns([]*nftables.Rule{}, nil)
	})

	Describe("SetupMonitFirewall", func() {
		Context("on fresh install (no existing rules)", func() {
			It("creates table, chains, and rules successfully", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddTableCallCount()).To(Equal(1))
				Expect(fakeConn.AddChainCallCount()).To(Equal(2)) // monit_output_jobs + monit_output
				Expect(fakeConn.GetRulesCallCount()).To(Equal(1))
				// 2 InsertRule (jump + allow) + 1 AddRule (block)
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(2))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(1))
				Expect(fakeConn.FlushCallCount()).To(Equal(1))
			})

			It("creates table with correct configuration", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				table := fakeConn.AddTableArgsForCall(0)
				Expect(table.Name).To(Equal("filter"))
				Expect(table.Family).To(Equal(nftables.TableFamilyINet))
			})

			It("creates monit chain with correct configuration", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// First chain is monit_output_jobs (regular chain, no hook)
				jobsChain := fakeConn.AddChainArgsForCall(0)
				Expect(jobsChain.Name).To(Equal("monit_output_jobs"))
				Expect(jobsChain.Type).To(Equal(nftables.ChainType(""))) // Regular chain has no type

				// Second chain is monit_output (base chain with hook)
				monitChain := fakeConn.AddChainArgsForCall(1)
				Expect(monitChain.Name).To(Equal("monit_output"))
				Expect(monitChain.Type).To(Equal(nftables.ChainTypeFilter))
				Expect(monitChain.Hooknum).NotTo(BeNil())
				Expect(*monitChain.Hooknum).To(Equal(*nftables.ChainHookOutput))
			})

			It("inserts jump rule and allow rule at beginning of chain", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// First InsertRule call is the allow rule (inserted second, so becomes index 1)
				// Second InsertRule call is the jump rule (inserted first, so becomes index 0)
				// Note: InsertRule prepends, so rules are processed in reverse order
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(2))

				// Jump rule (inserted last, so it's the first rule)
				jumpRule := fakeConn.InsertRuleArgsForCall(1)
				Expect(jumpRule.Chain.Name).To(Equal("monit_output"))
				Expect(len(jumpRule.Exprs)).To(Equal(1))
				verdict, ok := jumpRule.Exprs[0].(*expr.Verdict)
				Expect(ok).To(BeTrue())
				Expect(verdict.Kind).To(Equal(expr.VerdictJump))
				Expect(verdict.Chain).To(Equal("monit_output_jobs"))

				// Allow rule (inserted first, so it becomes second rule)
				allowRule := fakeConn.InsertRuleArgsForCall(0)
				Expect(allowRule.Chain.Name).To(Equal("monit_output"))
				// Allow rule has UID match + loopback + port + accept
				Expect(len(allowRule.Exprs)).To(BeNumerically(">", 5))

				// Last expression should be accept verdict
				acceptVerdict, ok := allowRule.Exprs[len(allowRule.Exprs)-1].(*expr.Verdict)
				Expect(ok).To(BeTrue())
				Expect(acceptVerdict.Kind).To(Equal(expr.VerdictAccept))
			})

			It("marks all agent rules with UserData", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Check all InsertRule calls have marker
				for i := 0; i < fakeConn.InsertRuleCallCount(); i++ {
					rule := fakeConn.InsertRuleArgsForCall(i)
					Expect(string(rule.UserData)).To(Equal("bosh-agent"))
				}

				// Check AddRule calls have marker
				for i := 0; i < fakeConn.AddRuleCallCount(); i++ {
					rule := fakeConn.AddRuleArgsForCall(i)
					Expect(string(rule.UserData)).To(Equal("bosh-agent"))
				}
			})

			It("adds block rule at end of chain", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Block rule is added (appended) to be last
				blockRule := fakeConn.AddRuleArgsForCall(0)
				Expect(blockRule.Chain.Name).To(Equal("monit_output"))

				// Last expression should be drop verdict
				verdict, ok := blockRule.Exprs[len(blockRule.Exprs)-1].(*expr.Verdict)
				Expect(ok).To(BeTrue())
				Expect(verdict.Kind).To(Equal(expr.VerdictDrop))
			})
		})

		Context("when rules already exist and match desired state", func() {
			BeforeEach(func() {
				// Simulate existing agent rules that match desired state
				existingRules := []*nftables.Rule{
					{
						Handle:   1,
						UserData: []byte("bosh-agent"),
						Exprs:    buildJumpExprs(),
					},
					{
						Handle:   2,
						UserData: []byte("bosh-agent"),
						Exprs:    buildAllowExprs(),
					},
					{
						Handle:   3,
						UserData: []byte("bosh-agent"),
						Exprs:    buildBlockExprs(),
					},
				}
				fakeConn.GetRulesReturns(existingRules, nil)
			})

			It("does not modify rules (idempotent)", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Should not delete or add any rules
				Expect(fakeConn.DelRuleCallCount()).To(Equal(0))
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(0))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(0))
			})
		})

		Context("when job rules exist alongside agent rules", func() {
			BeforeEach(func() {
				// Simulate agent rules + a job rule (no UserData marker)
				existingRules := []*nftables.Rule{
					{
						Handle:   1,
						UserData: []byte("bosh-agent"),
						Exprs:    buildJumpExprs(),
					},
					{
						Handle:   2,
						UserData: []byte("bosh-agent"),
						Exprs:    buildAllowExprs(),
					},
					{
						Handle:   3,
						UserData: nil, // Job rule - no marker
						Exprs: []expr.Any{
							// Some job-specific expressions (e.g., cgroup match)
							&expr.Verdict{Kind: expr.VerdictAccept},
						},
					},
					{
						Handle:   4,
						UserData: []byte("bosh-agent"),
						Exprs:    buildBlockExprs(),
					},
				}
				fakeConn.GetRulesReturns(existingRules, nil)
			})

			It("preserves job rules and does not modify agent rules when matching", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Should not delete job rule (handle 3)
				// Agent rules match, so no changes needed
				Expect(fakeConn.DelRuleCallCount()).To(Equal(0))
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(0))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(0))
			})
		})

		Context("when agent rules are missing but job rules exist", func() {
			BeforeEach(func() {
				// Only a job rule exists, no agent rules
				existingRules := []*nftables.Rule{
					{
						Handle:   1,
						UserData: nil, // Job rule
						Exprs: []expr.Any{
							&expr.Verdict{Kind: expr.VerdictAccept},
						},
					},
				}
				fakeConn.GetRulesReturns(existingRules, nil)
			})

			It("adds agent rules while preserving job rules", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Should not delete the job rule
				Expect(fakeConn.DelRuleCallCount()).To(Equal(0))

				// Should add all agent rules: 2 InsertRule (jump + allow) + 1 AddRule (block)
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(2))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(1))
			})
		})

		Context("when agent rules have changed (need update)", func() {
			BeforeEach(func() {
				// Old agent rules that don't match current desired state
				existingRules := []*nftables.Rule{
					{
						Handle:   1,
						UserData: []byte("bosh-agent"),
						Exprs: []expr.Any{
							// Old/different expressions
							&expr.Verdict{Kind: expr.VerdictDrop},
						},
					},
				}
				fakeConn.GetRulesReturns(existingRules, nil)
			})

			It("deletes old agent rules and adds new ones", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Should delete the old agent rule
				Expect(fakeConn.DelRuleCallCount()).To(Equal(1))
				deletedRule := fakeConn.DelRuleArgsForCall(0)
				Expect(deletedRule.Handle).To(Equal(uint64(1)))

				// Should add all new agent rules: 2 InsertRule (jump + allow) + 1 AddRule (block)
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(2))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(1))
			})
		})

		Context("when GetRules fails", func() {
			BeforeEach(func() {
				fakeConn.GetRulesReturns(nil, errors.New("chain not found"))
			})

			It("treats as empty and adds all rules", func() {
				err := manager.SetupMonitFirewall()
				Expect(err).NotTo(HaveOccurred())

				// Should add all agent rules: 2 InsertRule (jump + allow) + 1 AddRule (block)
				Expect(fakeConn.InsertRuleCallCount()).To(Equal(2))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(1))
			})
		})

		Context("when Flush fails", func() {
			It("returns an error", func() {
				fakeConn.FlushReturns(errors.New("flush failed"))

				err := manager.SetupMonitFirewall()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Flushing nftables rules"))
			})
		})
	})

	Describe("SetupNATSFirewall", func() {
		Context("with an IPv4 address URL", func() {
			It("creates rules for the IPv4 address", func() {
				err := manager.SetupNATSFirewall("nats://user:pass@192.168.1.100:4222")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddTableCallCount()).To(Equal(1))
				Expect(fakeConn.AddChainCallCount()).To(Equal(1))
				Expect(fakeConn.FlushChainCallCount()).To(Equal(1))
				// One allow rule + one block rule
				Expect(fakeConn.AddRuleCallCount()).To(Equal(2))
				Expect(fakeConn.FlushCallCount()).To(Equal(1))
			})

			It("creates chain with correct configuration", func() {
				err := manager.SetupNATSFirewall("nats://192.168.1.100:4222")
				Expect(err).NotTo(HaveOccurred())

				chain := fakeConn.AddChainArgsForCall(0)
				Expect(chain.Name).To(Equal("nats_output"))
				Expect(chain.Type).To(Equal(nftables.ChainTypeFilter))
				Expect(chain.Hooknum).To(Equal(nftables.ChainHookOutput))
			})
		})

		Context("with an IPv6 address URL", func() {
			It("creates rules for the IPv6 address", func() {
				err := manager.SetupNATSFirewall("nats://user:pass@[2001:db8::1]:4222")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddRuleCallCount()).To(Equal(2))
				Expect(fakeConn.FlushCallCount()).To(Equal(1))
			})
		})

		Context("with a hostname URL", func() {
			It("resolves DNS and creates rules for resolved IPs", func() {
				fakeResolver.LookupIPReturns([]net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("10.0.0.2"),
				}, nil)

				err := manager.SetupNATSFirewall("nats://user:pass@nats.example.com:4222")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeResolver.LookupIPCallCount()).To(Equal(1))
				Expect(fakeResolver.LookupIPArgsForCall(0)).To(Equal("nats.example.com"))

				// Two IPs * 2 rules each = 4 rules
				Expect(fakeConn.AddRuleCallCount()).To(Equal(4))
			})

			It("handles DNS resolution failure gracefully", func() {
				fakeResolver.LookupIPReturns(nil, errors.New("dns lookup failed"))

				err := manager.SetupNATSFirewall("nats://user:pass@nats.example.com:4222")
				Expect(err).NotTo(HaveOccurred()) // Should not return error, just log warning

				Expect(fakeResolver.LookupIPCallCount()).To(Equal(1))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(0)) // No rules added
			})
		})

		Context("with default port", func() {
			It("uses port 4222 when not specified", func() {
				err := manager.SetupNATSFirewall("nats://192.168.1.100")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddRuleCallCount()).To(Equal(2))
			})
		})

		Context("with custom port", func() {
			It("uses the specified port", func() {
				err := manager.SetupNATSFirewall("nats://192.168.1.100:5222")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddRuleCallCount()).To(Equal(2))
			})
		})

		Context("with https URL", func() {
			It("skips setup and returns nil", func() {
				err := manager.SetupNATSFirewall("https://director.example.com:25555")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddTableCallCount()).To(Equal(0))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(0))
			})
		})

		Context("with empty URL", func() {
			It("skips setup and returns nil", func() {
				err := manager.SetupNATSFirewall("")
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeConn.AddTableCallCount()).To(Equal(0))
				Expect(fakeConn.AddRuleCallCount()).To(Equal(0))
			})
		})

		Context("when called multiple times", func() {
			It("flushes existing NATS chain before adding new rules", func() {
				err := manager.SetupNATSFirewall("nats://192.168.1.100:4222")
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeConn.FlushChainCallCount()).To(Equal(1))

				err = manager.SetupNATSFirewall("nats://192.168.1.200:4222")
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeConn.FlushChainCallCount()).To(Equal(2))
			})
		})

		Context("when Flush fails", func() {
			It("returns an error", func() {
				fakeConn.FlushReturns(errors.New("flush failed"))

				err := manager.SetupNATSFirewall("nats://192.168.1.100:4222")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Flushing nftables rules"))
			})
		})
	})

	Describe("BeforeConnect", func() {
		var hook firewall.NatsFirewallHook

		BeforeEach(func() {
			hook = manager.(firewall.NatsFirewallHook)
		})

		It("delegates to SetupNATSFirewall", func() {
			err := hook.BeforeConnect("nats://192.168.1.100:4222")
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeConn.AddTableCallCount()).To(Equal(1))
			Expect(fakeConn.AddChainCallCount()).To(Equal(1))
			Expect(fakeConn.AddRuleCallCount()).To(Equal(2))
		})

		It("returns nil on success", func() {
			err := hook.BeforeConnect("nats://192.168.1.100:4222")
			Expect(err).NotTo(HaveOccurred())
		})

		It("returns error when SetupNATSFirewall fails", func() {
			fakeConn.FlushReturns(errors.New("flush failed"))

			err := hook.BeforeConnect("nats://192.168.1.100:4222")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Manager interface implementation", func() {
		It("implements NatsFirewallHook interface", func() {
			hook := manager.(firewall.NatsFirewallHook)
			Expect(hook).NotTo(BeNil())
		})
	})
})

// Helper functions to build expected expressions for tests
func buildJumpExprs() []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictJump, Chain: "monit_output_jobs"},
	}
}

func buildAllowExprs() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{127, 0, 0, 1}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x0b, 0x06}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func buildBlockExprs() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{127, 0, 0, 1}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x0b, 0x06}},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}
