package model

import "testing"

func TestComputeChange_Escalated(t *testing.T) {
	current := &Snapshot{CVEID: "CVE-2024-3094", Priority: PriorityCritical, EPSS: 0.95, InKEV: true}
	previous := &Snapshot{CVEID: "CVE-2024-3094", Priority: PriorityLow, EPSS: 0.12, InKEV: false}

	c := ComputeChange(current, previous)

	if c.Type != ChangeEscalated {
		t.Errorf("Type = %v, want %v", c.Type, ChangeEscalated)
	}
	if !c.KEVAdded {
		t.Error("KEVAdded = false, want true")
	}
	if c.OldPriority != PriorityLow {
		t.Errorf("OldPriority = %v, want %v", c.OldPriority, PriorityLow)
	}
	if c.NewPriority != PriorityCritical {
		t.Errorf("NewPriority = %v, want %v", c.NewPriority, PriorityCritical)
	}
}

func TestComputeChange_Deescalated(t *testing.T) {
	current := &Snapshot{CVEID: "CVE-2024-0001", Priority: PriorityMinimal, EPSS: 0.01}
	previous := &Snapshot{CVEID: "CVE-2024-0001", Priority: PriorityHigh, EPSS: 0.8}

	c := ComputeChange(current, previous)

	if c.Type != ChangeDeescalated {
		t.Errorf("Type = %v, want %v", c.Type, ChangeDeescalated)
	}
}

func TestComputeChange_NewExploits(t *testing.T) {
	current := &Snapshot{CVEID: "CVE-2024-0002", Priority: PriorityHigh, Exploits: 3}
	previous := &Snapshot{CVEID: "CVE-2024-0002", Priority: PriorityHigh, Exploits: 1}

	c := ComputeChange(current, previous)

	if c.Type != ChangeNewExploits {
		t.Errorf("Type = %v, want %v", c.Type, ChangeNewExploits)
	}
}

func TestComputeChange_EPSSMovement(t *testing.T) {
	current := &Snapshot{CVEID: "CVE-2024-0003", Priority: PriorityMedium, EPSS: 0.45}
	previous := &Snapshot{CVEID: "CVE-2024-0003", Priority: PriorityMedium, EPSS: 0.30}

	c := ComputeChange(current, previous)

	if c.Type != ChangeEPSSMovement {
		t.Errorf("Type = %v, want %v", c.Type, ChangeEPSSMovement)
	}
	if c.EPSSDelta < 0.14 || c.EPSSDelta > 0.16 {
		t.Errorf("EPSSDelta = %v, want ~0.15", c.EPSSDelta)
	}
}

func TestComputeChange_Stable(t *testing.T) {
	current := &Snapshot{CVEID: "CVE-2024-0004", Priority: PriorityMedium, EPSS: 0.30, CVSS: 7.5}
	previous := &Snapshot{CVEID: "CVE-2024-0004", Priority: PriorityMedium, EPSS: 0.30, CVSS: 7.5}

	c := ComputeChange(current, previous)

	if c.Type != ChangeStable {
		t.Errorf("Type = %v, want %v", c.Type, ChangeStable)
	}
}

func TestComputeChange_NoPrevious(t *testing.T) {
	current := &Snapshot{CVEID: "CVE-2024-0005", Priority: PriorityHigh}

	c := ComputeChange(current, nil)

	if c.Type != ChangeNew {
		t.Errorf("Type = %v, want %v", c.Type, ChangeNew)
	}
}

func TestComputeChange_SmallEPSSIgnored(t *testing.T) {
	// Small EPSS fluctuation (< 0.02 absolute and < 20% relative) should be stable
	current := &Snapshot{CVEID: "CVE-2024-0006", Priority: PriorityMedium, EPSS: 0.31}
	previous := &Snapshot{CVEID: "CVE-2024-0006", Priority: PriorityMedium, EPSS: 0.30}

	c := ComputeChange(current, previous)

	if c.Type != ChangeStable {
		t.Errorf("Type = %v, want %v (small EPSS change should be ignored)", c.Type, ChangeStable)
	}
}


func TestIsSignificantEPSSChange(t *testing.T) {
	tests := []struct {
		old, new float64
		want     bool
	}{
		{0.30, 0.50, true},   // +66% relative, +0.20 absolute
		{0.30, 0.31, false},  // +3% relative, +0.01 absolute (below both thresholds)
		{0.30, 0.33, true},   // +10% relative but +0.03 absolute > 0.02
		{0.00, 0.05, true},   // from zero
		{0.05, 0.00, true},   // to zero
		{0.50, 0.50, false},  // no change
		{0.10, 0.005, true},  // large relative drop
	}

	for _, tt := range tests {
		got := isSignificantEPSSChange(tt.old, tt.new)
		if got != tt.want {
			t.Errorf("isSignificantEPSSChange(%v, %v) = %v, want %v", tt.old, tt.new, got, tt.want)
		}
	}
}
