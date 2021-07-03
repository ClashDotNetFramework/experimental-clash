package provider_test

import (
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/rule"
	ruleProvider "github.com/Dreamacro/clash/rule/provider"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

func setup() {
	ruleProvider.SetClassicalRuleParser(func(ruleType, rule string, params []string) (constant.Rule, error) {
		if params == nil {
			params = make([]string, 0)
		}

		return rules.ParseRule(ruleType, rule, "", params)
	})
}

func TestDomain(t *testing.T) {
	setup()
	domainProvider := ruleProvider.NewRuleSetProvider("test", ruleProvider.Domain,
		time.Duration(uint(100000)), provider.NewFileVehicle("./domain.txt"))
	assert.Nil(t, domainProvider.Initial())
	assert.True(t, domainProvider.Search(&constant.Metadata{Host: "youtube.com"}))
	assert.True(t, domainProvider.Search(&constant.Metadata{Host: "www.youtube.com"}))
	assert.True(t, domainProvider.Search(&constant.Metadata{Host: "test.youtube.com"}))
	assert.True(t, domainProvider.Search(&constant.Metadata{Host: "bcovlive-a.akamaihd.net"}))
	assert.False(t, domainProvider.Search(&constant.Metadata{Host: "baidu.com"}))
}

func TestClassical(t *testing.T) {
	setup()
	classicalProvider := ruleProvider.NewRuleSetProvider("test", ruleProvider.Classical,
		time.Duration(uint(100000)), provider.NewFileVehicle("./classical.txt"))
	assert.Nil(t, classicalProvider.Initial())
	assert.True(t, classicalProvider.Search(&constant.Metadata{Host: "www.10010.com", AddrType: constant.AtypDomainName}))
	assert.False(t, classicalProvider.Search(&constant.Metadata{Host: "google.com", AddrType: constant.AtypDomainName}))
	assert.True(t, classicalProvider.Search(&constant.Metadata{Host: "analytics.strava.com", AddrType: constant.AtypDomainName}))
	assert.True(t, classicalProvider.Search(&constant.Metadata{DstIP: net.ParseIP("2a0b:b580::1")}))
	assert.False(t, classicalProvider.Search(&constant.Metadata{DstIP: net.ParseIP("2a0b:c582::1")}))
	assert.True(t, classicalProvider.Search(&constant.Metadata{DstIP: net.ParseIP("1.255.62.34")}))
	assert.False(t, classicalProvider.Search(&constant.Metadata{DstIP: net.ParseIP("103.65.41.199")}))
}

func TestIpCidr(t *testing.T) {
	setup()
	domainProvider := ruleProvider.NewRuleSetProvider("test", ruleProvider.IPCIDR,
		time.Duration(uint(100000)), provider.NewFileVehicle("./ipcidr.txt"))
	assert.Nil(t, domainProvider.Initial())
	assert.True(t, domainProvider.Search(&constant.Metadata{DstIP: net.ParseIP("91.108.22.10")}))
	assert.False(t, domainProvider.Search(&constant.Metadata{DstIP: net.ParseIP("149.190.220.251")}))
	assert.True(t, domainProvider.Search(&constant.Metadata{DstIP: net.ParseIP("2001:b28:f23f:f005::a")}))
	assert.False(t, domainProvider.Search(&constant.Metadata{DstIP: net.ParseIP("2006:b28:f23f:f005::a")}))
}
