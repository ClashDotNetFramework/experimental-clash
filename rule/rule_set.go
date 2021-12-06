package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rule/provider"
)

type RuleSet struct {
	ruleProviderName string
	adapter          string
	ruleProvider     *provider.RuleProvider
}

func (rs *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (rs *RuleSet) Match(metadata *C.Metadata) bool {
	return rs.getProviders().Search(metadata)
}

func (rs *RuleSet) Adapter() string {
	return rs.adapter
}

func (rs *RuleSet) Payload() string {
	return rs.getProviders().Name()
}

func (rs *RuleSet) ShouldResolveIP() bool {
	return rs.getProviders().Behavior() != provider.Domain
}

func (rs *RuleSet) getProviders() provider.RuleProvider {
	if rs.ruleProvider == nil {
		rp := provider.RuleProviders()[rs.ruleProviderName]
		rs.ruleProvider = rp
	}

	return *rs.ruleProvider
}

func NewRuleSet(ruleProviderName string, adapter string) (*RuleSet, error) {
	rp, ok := provider.RuleProviders()[ruleProviderName]
	if !ok {
		return nil, fmt.Errorf("rule set %s not found", ruleProviderName)
	}
	return &RuleSet{
		ruleProviderName: ruleProviderName,
		adapter:          adapter,
		ruleProvider:     rp,
	}, nil
}
