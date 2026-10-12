package checks

import (
	"fmt"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

type outboundCheck struct{}

func (outboundCheck) Type() string { return plugins.CheckOutboundTCP }
func (outboundCheck) Cost() int    { return plugins.BuiltinCosts()[plugins.CheckOutboundTCP] }

func (outboundCheck) Run(in Input) Outcome {
	n := in.Spec.Consecutive
	if n < 1 {
		n = 1
	}
	port := in.Spec.Port
	roots := sysprobe.RootPIDsSpec(in.Snap, in.Plugin.Process.Spec())
	count := sysprobe.CountOutbound(in.Snap, roots, port)
	if in.Streak == nil {
		zero := 0
		in.Streak = &zero
	}
	if count > 0 {
		*in.Streak = 0
		return Outcome{
			Type:    plugins.CheckOutboundTCP,
			Healthy: true,
			Detail:  fmt.Sprintf("established outbound connections to port %d: %d", port, count),
		}
	}
	*in.Streak++
	detail := fmt.Sprintf("established outbound connections to port %d: 0 (streak %d of %d)", port, *in.Streak, n)
	if *in.Streak >= n {
		return Outcome{
			Type:   plugins.CheckOutboundTCP,
			Failed: true,
			Stuck:  true,
			Detail: detail,
		}
	}
	return Outcome{
		Type:    plugins.CheckOutboundTCP,
		Healthy: false,
		Detail:  detail,
	}
}
