package trie

import "testing"
import "github.com/stretchr/testify/assert"

func TestAddSuccess(t *testing.T) {
	trie := NewIpCidrTrie()
	err := trie.AddIpCidr("10.0.0.2/16")
	assert.Equal(t, nil, err)
}
func TestAddFail(t *testing.T) {
	trie := NewIpCidrTrie()
	err := trie.AddIpCidr("333.00.23.2/23")
	assert.Equal(t, ErrInvalidIpFormat, err)

	err = trie.AddIpCidr("22.3.34.2/222")
	assert.Equal(t, ErrInvalidIpCidrFormat, err)

	err = trie.AddIpCidr("2.2.2.2")
	assert.Equal(t, ErrInvalidIpCidrFormat, err)
}

func TestSearch(t *testing.T) {
	trie := NewIpCidrTrie()
	assert.NoError(t, trie.AddIpCidr("129.2.36.0/16"))
	assert.NoError(t, trie.AddIpCidr("10.2.36.0/18"))
	assert.NoError(t, trie.AddIpCidr("16.2.23.0/24"))
	assert.NoError(t, trie.AddIpCidr("11.2.13.2/26"))
	assert.NoError(t, trie.AddIpCidr("55.5.6.3/8"))
	assert.NoError(t, trie.AddIpCidr("66.23.25.4/6"))
	assert.Equal(t, true, trie.IsContain("129.2.3.65"))
	assert.Equal(t, false, trie.IsContain("15.2.3.1"))
	assert.Equal(t, true, trie.IsContain("11.2.13.1"))
	assert.Equal(t, true, trie.IsContain("55.0.0.0"))
	assert.Equal(t, true, trie.IsContain("64.0.0.0"))
	assert.Equal(t, false, trie.IsContain("128.0.0.0"))
}
