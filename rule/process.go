package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/process"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var processCache = cache.NewLRUCache(cache.WithAge(2), cache.WithSize(64))

type Process struct {
	adapter string
	process string
	fullMatch bool
}

func (ps *Process) RuleType() C.RuleType {
	return C.Process
}

func (ps *Process) Match(metadata *C.Metadata) bool {
	key := fmt.Sprintf("%s:%s:%s", metadata.NetWork.String(), metadata.SrcIP.String(), metadata.SrcPort)
	cached, hit := processCache.Get(key)
	if !hit {
		srcPort, err := strconv.Atoi(metadata.SrcPort)
		if err != nil {
			processCache.Set(key, "")
			return false
		}

		name, err := process.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, srcPort)
		if err != nil {
			log.Debugln("[Rule] find process name %s error: %s", C.Process.String(), err.Error())
		}

		processCache.Set(key, name)

		cached = name
	}

	processName := cached.(string)
	if !ps.fullMatch {
		processName = filepath.Base(processName)
	}

	return strings.EqualFold(processName, ps.process)
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) Payload() string {
	return ps.process
}

func (ps *Process) ShouldResolveIP() bool {
	return false
}

func NewProcess(process string, adapter string, fullMatch bool) (*Process, error) {
	if !fullMatch {
		process = filepath.Base(process)
	}

	return &Process{
		adapter: adapter,
		process: process,
		fullMatch: fullMatch,
	}, nil
}
