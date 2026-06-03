// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

type VmaKind uint32

// Only VMAs we are not ignoring (those are already discarded by the executor,
// as there is no point in collecting them)
const (
	VmaKindUnknown VmaKind = iota
	VmaKindStack
	VmaKindHeap
	VmaKindExecutorBinary
	VmaKindAnonymousPage
	VmaKindVdso
	VmaKindSyzkallerMmap
)

func (k VmaKind) String() string {
	switch k {
	case VmaKindStack:
		return "Stack"
	case VmaKindHeap:
		return "Heap"
	case VmaKindExecutorBinary:
		return "ExecutorBinary"
	case VmaKindAnonymousPage:
		return "AnonymousPage"
	case VmaKindVdso:
		return "Vdso"
	case VmaKindSyzkallerMmap:
		return "SyzkallerMmap"
	default:
		return "Unknown"
	}
}

func classifyVMA(name string, start uint64) VmaKind {
	if name != "" {
		switch name {
		case "[stack]":
			return VmaKindStack
		case "[heap]":
			return VmaKindHeap
		case "[vdso]":
			return VmaKindVdso
		}
		if strings.Contains(name, "/syz-executor") {
			return VmaKindExecutorBinary
		}
		return VmaKindUnknown
	}
	if (start & 0xFFF000000000) == 0x200000000000 {
		return VmaKindSyzkallerMmap
	}
	return VmaKindAnonymousPage
}

type ComparisonStrategy int

const (
	StrategyIgnore ComparisonStrategy = iota
	StrategySelfCheck
	StrategyCrossCompare
)

func getComparisonStrategy(kind VmaKind) ComparisonStrategy {
	switch kind {
	// Disabled for MVP - easily re-enablable later.
	// case VmaKindStack, VmaKindHeap, VmaKindVdso, VmaKindExecutorBinary:
	//
	//	return StrategySelfCheck
	case VmaKindSyzkallerMmap: // MVP currently focuses only on syzkaller scratchpad (0x2000...)
		return StrategyCrossCompare
	// case VmaKindAnonymousPage:
	//
	//	return StrategyCrossCompare
	default:
		return StrategyIgnore
	}
}

type VmaState struct {
	Hash uint32
	Kind VmaKind
}

func mapVMAs(rawVMAs []*flatrpc.VmaRawT) map[uint64]VmaState {
	vmaMap := make(map[uint64]VmaState, len(rawVMAs))
	for _, raw := range rawVMAs {
		vmaMap[raw.Start] = VmaState{
			Hash: raw.MemoryHash,
			Kind: classifyVMA(raw.Name, raw.Start),
		}
	}
	return vmaMap
}

func (vrf *Verifier) verifyMemoryMismatches(info0, info1 *flatrpc.ProgInfoRawT, kernelName0, kernelName1 string) (bool, string) {
	snap0 := mapVMAs(info0.SnapshotVmas)
	snap1 := mapVMAs(info1.SnapshotVmas)
	after0 := mapVMAs(info0.AfterVmas)
	after1 := mapVMAs(info1.AfterVmas)

	mismatchFound := false
	var report strings.Builder

	for start, vma0 := range snap0 {
		strategy := getComparisonStrategy(vma0.Kind)

		if strategy == StrategyIgnore {
			continue
		}

		if strategy == StrategySelfCheck {
			if a0, exists := after0[start]; exists {
				if vma0.Hash != a0.Hash {
					mismatchFound = true
					report.WriteString(fmt.Sprintf("Self-Check Mismatch (%s): %s mutated during execution.\n", kernelName0, vma0.Kind))
				}
			}
			if vma1, exists := snap1[start]; exists {
				if a1, existsAfter := after1[start]; existsAfter {
					if vma1.Hash != a1.Hash {
						mismatchFound = true
						report.WriteString(fmt.Sprintf("Self-Check Mismatch (%s): %s mutated during execution.\n", kernelName1, vma1.Kind))
					}
				}
			}
			continue
		}

		if strategy == StrategyCrossCompare {
			a0, exists0 := after0[start]
			a1, exists1 := after1[start]

			if exists0 && exists1 {
				if a0.Hash != a1.Hash {
					mismatchFound = true
					report.WriteString(fmt.Sprintf("Cross-Kernel Mismatch: %s at 0x%x diverged.\n", vma0.Kind, start))
					report.WriteString(fmt.Sprintf("\t%s Hash: 0x%x\n", kernelName0, a0.Hash))
					report.WriteString(fmt.Sprintf("\t%s Hash: 0x%x\n", kernelName1, a1.Hash))
				}
			}
		}
	}

	return mismatchFound, report.String()
}

// verifyDeepMemoryMismatches analyzes the Deep Mode CallVmas arrays.
// It returns the index of the first syscall where memory diverged, or -1 if none found.
func (vrf *Verifier) verifyDeepMemoryMismatches(info0, info1 *flatrpc.ProgInfoRawT) int {
	minCalls := min(len(info0.CallVmas), len(info1.CallVmas))

	for i := 0; i < minCalls; i++ {
		// If a kernel failed to produce VMAs for this call, that's our divergence.
		if info0.CallVmas[i] == nil || info1.CallVmas[i] == nil {
			return i
		}

		vmas0 := mapVMAs(info0.CallVmas[i].Vmas)
		vmas1 := mapVMAs(info1.CallVmas[i].Vmas)

		for start, v0 := range vmas0 {
			strategy := getComparisonStrategy(v0.Kind)
			if strategy == StrategyCrossCompare {
				if v1, exists := vmas1[start]; exists {
					if v0.Hash != v1.Hash {
						return i // Found the exact divergence point.
					}
				}
			}
		}
	}
	return -1
}

// logMemoryMismatchSequence is a temporary, isolated logger to avoid merge conflicts.
func (vrf *Verifier) logMemoryMismatchSequence(
	p *prog.Prog, info0, info1 *flatrpc.ProgInfoRawT, name0, name1 string,
	details string, divergentIdx int) {
	var reportBody strings.Builder
	writeLine := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		log.Logf(0, "%s", line)
		reportBody.WriteString(line)
		reportBody.WriteByte('\n')
	}

	writeLine("")
	writeLine("========== VMA MEMORY MISMATCH DETECTED ==========")
	writeLine("Between: Kernel 0 (%s) and Kernel 1 (%s)", name0, name1)
	writeLine("")
	for _, devLine := range strings.Split(strings.TrimSpace(details), "\n") {
		writeLine("%s", devLine)
	}
	writeLine("")
	writeLine("Complete Program Sequence:")
	writeLine("-------------------------------------------")

	progLines := strings.Split(strings.TrimSpace(string(p.Serialize())), "\n")
	for callIdx, call := range p.Calls {
		callStr := call.Meta.CallName + "(...)"
		if callIdx < len(progLines) {
			callStr = progLines[callIdx]
		}
		prefix := "   "
		if callIdx == divergentIdx {
			prefix = ">>>"
		}

		writeLine("%s [%d] %s", prefix, callIdx, callStr)

		if info0 != nil && info1 != nil && callIdx < len(info0.Calls) && callIdx < len(info1.Calls) {
			writeLine("%s      ┌─ %s: flags=0x%x", prefix, name0, uint8(info0.Calls[callIdx].Flags))
			writeLine("%s      └─ %s: flags=0x%x", prefix, name1, uint8(info1.Calls[callIdx].Flags))
		}
		writeLine("")
	}
	writeLine("-------------------------------------------")

	firstMismatchCall := "unknown"
	if divergentIdx >= 0 && divergentIdx < len(p.Calls) {
		firstMismatchCall = p.Calls[divergentIdx].Meta.CallName
	}
	title := fmt.Sprintf("syz-verifier memory mismatch: %s vs %s (%s)", name0, name1, firstMismatchCall)
	vrf.saveMismatchReport(title, reportBody.String())
}
