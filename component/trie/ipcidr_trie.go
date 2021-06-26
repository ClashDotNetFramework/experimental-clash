package trie

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrInvalidIpFormat     = errors.New("invalid ip format")
	ErrInvalidIpCidrFormat = errors.New("invalid ip cidr format")
)

const big = 0xFFFFFF

type IpCidrTrie struct {
	root IpCidrNode
}

func NewIpCidrTrie() *IpCidrTrie {
	return &IpCidrTrie{
		root: *NewIpCidrNode(false, true),
	}
}

func (trie *IpCidrTrie) AddIpCidr(ipCidr string) error {
	subIpCidr, subCidr, err := splitSubIpCidr(ipCidr)
	if err != nil {
		return err
	}
	for _, sub := range subIpCidr {
		addIpCidr(trie, sub, subCidr/8)
	}

	return nil
}
func (trie *IpCidrTrie) IsContain(ip string) bool {
	values := validAndObtainIp(ip)
	if values == nil {
		return false
	}
	return search(&trie.root, values) != nil

}
func validAndObtainIp(ip string) []uint8 {
	p := make([]uint8, 4)
	for i := 0; i < 4; i++ {
		if len(ip) == 0 {
			return nil
		}
		if i > 0 {
			if ip[0] != '.' {
				return nil
			}
			ip = ip[1:]
		}
		n, c, ok := dtoi(ip)
		if !ok || n > 0xFF {
			return nil
		}
		ip = ip[c:]
		p[i] = uint8(n)
	}
	return p
}
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

/**
Divide an ip cidr into multiple ip cidr whose subnet mask length is a multiple of 8
*/
func splitSubIpCidr(ipCidr string) ([][4]uint8, int, error) {
	p := strings.Split(ipCidr, "/")
	if len(p) != 2 {
		return nil, 0, ErrInvalidIpCidrFormat
	}
	uint8Ip := validAndObtainIp(p[0])
	if uint8Ip == nil {
		return nil, 0, ErrInvalidIpFormat
	}
	cidr, err := strconv.Atoi(p[1])
	if err != nil || (cidr < 0 || cidr > 32) {
		return nil, 0, ErrInvalidIpCidrFormat
	}
	if cidr == 0 {
		return make([][4]uint8, 1), 0, nil
	}

	cidrIndex := cidr / 8
	subIpCidr := make([][4]uint8, 0)

	lastIndexCidrNum := cidr % 8
	if lastIndexCidrNum == 0 {
		index := cidrIndex
		if cidrIndex > 3 {
			index = 3
		}
		ipCidr := [4]uint8{}
		for i := 0; i <= index; i++ {
			ipCidr[i] = uint8Ip[i]
		}
		subIpCidr = append(subIpCidr, ipCidr)
		return subIpCidr, cidrIndex * 8, nil
	}

	subIpCidrNum := uint8Ip[cidrIndex] & (0xFF >> lastIndexCidrNum)
	var endCidr uint8 = 0

	endCidr = uint8Ip[cidrIndex] & uint8(0xFF<<(8-lastIndexCidrNum))
	for i := 0; i < int(subIpCidrNum); i++ {
		j := 0
		sub := [4]uint8{}
		for ; j < cidrIndex; j++ {
			sub[j] = 0xff & uint8Ip[j]
		}
		sub[j] = endCidr + uint8(i)
		subIpCidr = append(subIpCidr, sub)
	}
	return subIpCidr, (cidrIndex + 1) * 8, nil
}

func addIpCidr(trie *IpCidrTrie, ip [4]uint8, cidrByteSize int) {
	node := trie.root.getChild(ip[0])

	for i := 1; i < cidrByteSize; i++ {
		if node.Tag {
			return
		}
		if !node.hasChild(ip[i]) {
			node.addChild(ip[i])
		}
		node = node.getChild(ip[i])
	}
	node.Tag = true
	cleanChild(node)
}
func cleanChild(node *IpCidrNode) {
	for i := 0; i < len(node.child); i++ {
		node.child[i] = nil
	}
}

func search(root *IpCidrNode, partValues []uint8) *IpCidrNode {
	node := root.getChild(partValues[0])
	if node.Tag {
		return node
	}
	for _, value := range partValues[1:] {
		if !node.hasChild(value) {
			return nil
		}
		node = node.getChild(value)

		if node.Tag {
			return node
		}
	}
	return nil
}
