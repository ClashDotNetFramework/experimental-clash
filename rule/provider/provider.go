package provider

import (
	"encoding/json"
	"errors"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	R "github.com/Dreamacro/clash/rule"
	"gopkg.in/yaml.v2"
	"runtime"
	"strings"
	"time"
)

type Behavior int

const (
	Domain Behavior = iota
	IPCIDR
	Classical
)

func (b Behavior) String() string {
	switch b {
	case Domain:
		return "Domain"
	case IPCIDR:
		return "IPCIDR"
	case Classical:
		return "Classical"
	default:
		return ""
	}
}

type RuleProvider interface {
	provider.Provider
	Search(metadata *C.Metadata) bool
	RuleCount() int
	Behavior() Behavior
}
type ruleSetProvider struct {
	*fetcher
	behavior       Behavior
	count          int
	DomainRules    *trie.DomainTrie
	IPCIDRRules    *trie.IpCidrTrie
	ClassicalRules []C.Rule
}

type RuleSetProvider struct {
	*ruleSetProvider
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Rules []string `yaml:"payload"`
}

func NewRuleSetProvider(name string, behavior Behavior, interval time.Duration, vehicle provider.Vehicle) RuleProvider {
	rp := &ruleSetProvider{
		behavior: behavior,
	}
	onUpdate := func(elm interface{}) error {
		rulesRaw := elm.([]string)
		rp.count = len(rulesRaw)
		rules, err := constructRules(rp.behavior, rulesRaw)
		if err != nil {
			return err
		}
		rp.setRules(rules)
		return nil
	}

	fetcher := newFetcher(name, interval, vehicle, rulesParse, onUpdate)
	rp.fetcher = fetcher
	wrapper := &RuleSetProvider{
		rp,
	}
	runtime.SetFinalizer(wrapper, stopRuleSetProvider)
	return wrapper
}
func (rp *ruleSetProvider) Name() string {
	return rp.name
}

func (rp *ruleSetProvider) RuleCount() int {
	return rp.count
}
func (rp *ruleSetProvider) Search(metadata *C.Metadata) bool {
	switch rp.behavior {
	case Domain:
		return rp.DomainRules.Search(metadata.Host) != nil
	case IPCIDR:
		return rp.IPCIDRRules.IsContain(metadata.DstIP.String())
	case Classical:
		for _, rule := range rp.ClassicalRules {
			if rule.Match(metadata) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (rp *ruleSetProvider) Behavior() Behavior {
	return rp.behavior
}
func (rp *ruleSetProvider) VehicleType() provider.VehicleType {
	return rp.vehicle.Type()
}

func (rp *ruleSetProvider) Type() provider.ProviderType {
	return provider.Rule
}

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.fetcher.Initial()
	if err != nil {
		return err
	}
	return rp.fetcher.onUpdate(elm)
}

func (rp *ruleSetProvider) Update() error {
	elm, same, err := rp.fetcher.Update()
	if err == nil && !same {
		return rp.fetcher.onUpdate(elm)
	}
	return err
}
func (rp *ruleSetProvider) setRules(rules interface{}) {
	switch rp.behavior {
	case Domain:
		rp.DomainRules = rules.(*trie.DomainTrie)
	case Classical:
		rp.ClassicalRules = rules.([]C.Rule)
	case IPCIDR:
		rp.IPCIDRRules = rules.(*trie.IpCidrTrie)
	default:
	}
}
func (rp ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"behavior":    rp.behavior.String(),
			"name":        rp.Name(),
			"ruleCount":   rp.RuleCount(),
			"type":        rp.Type().String(),
			"updatedAt":   rp.updatedAt,
			"vehicleType": rp.VehicleType().String(),
		})
}
func rulesParse(buf []byte) (interface{}, error) {
	rulePayload := RulePayload{}
	err := yaml.Unmarshal(buf, &rulePayload)
	if err != nil {
		return nil, err
	}
	return rulePayload.Rules, nil
}

func constructRules(behavior Behavior, rules []string) (interface{}, error) {
	switch behavior {
	case Domain:
		return handleDomainRules(rules)
	case IPCIDR:
		return handleIpCidrRules(rules)
	case Classical:
		return handleClassicalRules(rules)
	default:
		return nil, errors.New("unknown behavior type")
	}
}
func handleDomainRules(rules []string) (interface{}, error) {
	domainRules := trie.New()
	for _, rawRule := range rules {
		ruleType, rule, _ := ruleParse(rawRule)
		if ruleType != "" {
			return nil, errors.New("error format of domain")
		}
		if err := domainRules.Insert(rule, nil); err != nil {
			return nil, err
		}
	}
	return domainRules, nil
}
func handleIpCidrRules(rules []string) (interface{}, error) {
	ipCidrRules := trie.NewIpCidrTrie()
	for _, rawRule := range rules {
		ruleType, rule, _ := ruleParse(rawRule)
		if ruleType != "" {
			return nil, errors.New("error format of ip-cidr")
		}
		if err := ipCidrRules.AddIpCidr(rule); err != nil {
			return nil, err
		}
	}
	return ipCidrRules, nil
}
func handleClassicalRules(rules []string) (interface{}, error) {
	var classicalRules []C.Rule
	for _, rawRule := range rules {
		ruleType, rule, params := ruleParse(rawRule)
		if ruleType == "RULE-SET" {
			return nil, errors.New("error rule type")
		}
		r, err := R.ParseRule(ruleType, rule, "", params)
		if err != nil {
			return nil, err
		}
		classicalRules = append(classicalRules, r)
	}
	return classicalRules, nil
}
func ruleParse(ruleRaw string) (string, string, []string) {

	item := strings.Split(ruleRaw, ",")
	if len(item) == 1 {
		return "", item[0], nil
	} else if len(item) == 2 {
		return item[0], item[1], nil
	} else if len(item) > 2 {
		return item[0], item[1], item[2:]
	}
	return "", "", nil
}

func stopRuleSetProvider(rp *RuleSetProvider) {
	rp.fetcher.Destroy()
}
