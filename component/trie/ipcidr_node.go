package trie

const ()

type IpCidrNode struct {
	Tag   bool
	child [256]*IpCidrNode
}

func NewIpCidrNode(tag bool, initChild bool) *IpCidrNode {
	ipCidrNode := &IpCidrNode{
		Tag:   tag,
		child: [256]*IpCidrNode{},
	}

	if initChild {
		for i := 0; i < 256; i++ {
			ipCidrNode.child[i] = NewIpCidrNode(false, false)
		}
	}

	return ipCidrNode
}

func (n *IpCidrNode) addChild(value uint8) {
	n.child[value] = NewIpCidrNode(false, false)
}

func (n *IpCidrNode) hasChild(value uint8) bool {
	return !n.Tag && n.child[value] != nil
}

func (n *IpCidrNode) getChild(value uint8) *IpCidrNode {
	if !n.Tag {
		return n.child[value]
	}

	return nil
}
