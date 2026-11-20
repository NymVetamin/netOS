//go:build !linux

package channels

type ruleWatch int

func watchIPv4Rules() (ruleWatch, bool) { return -1, false }
func (ruleWatch) unchanged() bool       { return false }
func (ruleWatch) close()                {}
