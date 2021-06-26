package provider

import (
	C "github.com/Dreamacro/clash/constant"
)

type RuleSet struct {
	ruleProvider RuleProvider
	adapter      string
}

func (rs *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (rs *RuleSet) Match(metadata *C.Metadata) bool {
	return rs.ruleProvider.Search(metadata)
}

func (rs *RuleSet) Adapter() string {
	return rs.adapter
}

func (rs *RuleSet) Payload() string {
	return rs.ruleProvider.Name()
}

func (rs *RuleSet) ShouldResolveIP() bool {
	return rs.ruleProvider.Behavior() != Domain
}

func NewRuleSet(ruleProvider RuleProvider, adapter string) *RuleSet {
	return &RuleSet{
		ruleProvider: ruleProvider,
		adapter:      adapter,
	}
}
