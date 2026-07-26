package tools

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// ErrKaliRuntimeRequired keeps active tooling dark outside the reproducible
// environment while passive commands remain available.
var ErrKaliRuntimeRequired = errors.New("active security adapters require Sentinel's Kali runtime; run `make dev` and reopen the repository in the Dev Container")

// BinaryRequirement describes one expected Kali toolchain component.
type BinaryRequirement struct {
	Name        string
	Binary      string
	InstallHint string
}

// BinaryStatus reports one requirement's local availability.
type BinaryStatus struct {
	BinaryRequirement
	Path      string `json:"path,omitempty"`
	Available bool   `json:"available"`
}

// RuntimeStatus is the complete doctor result.
type RuntimeStatus struct {
	GOOS        string         `json:"goos"`
	GOARCH      string         `json:"goarch"`
	InContainer bool           `json:"in_container"`
	Kali        bool           `json:"kali"`
	Ready       bool           `json:"ready"`
	Tools       []BinaryStatus `json:"tools"`
	Instruction string         `json:"instruction,omitempty"`
}

// KaliRequirements is the source of truth for tools doctor.
var KaliRequirements = []BinaryRequirement{
	{Name: "Aircrack-ng", Binary: "aircrack-ng", InstallHint: "package aircrack-ng"},
	{Name: "Hashcat", Binary: "hashcat", InstallHint: "package hashcat"},
	{Name: "hping3", Binary: "hping3", InstallHint: "package hping3"},
	{Name: "Kali DNS utilities", Binary: "dig", InstallHint: "package dnsutils"},
	{Name: "Metasploit", Binary: "msfconsole", InstallHint: "package metasploit-framework"},
	{Name: "nmap", Binary: "nmap", InstallHint: "package nmap"},
	{Name: "SET", Binary: "setoolkit", InstallHint: "package set"},
	{Name: "Skipfish", Binary: "skipfish", InstallHint: "package skipfish"},
	{Name: "sqlmap", Binary: "sqlmap", InstallHint: "package sqlmap"},
	{Name: "tshark", Binary: "tshark", InstallHint: "packages tshark and wireshark-common"},
	{Name: "WhatWeb", Binary: "whatweb", InstallHint: "package whatweb"},
}

// DetectRuntime inspects the host without changing it.
func DetectRuntime() RuntimeStatus {
	status := RuntimeStatus{
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		InContainer: inContainer(),
		Kali:        inKali(),
	}
	requirements := append([]BinaryRequirement(nil), KaliRequirements...)
	sort.Slice(requirements, func(i, j int) bool { return requirements[i].Name < requirements[j].Name })
	status.Tools = make([]BinaryStatus, 0, len(requirements))
	allPresent := true
	for _, requirement := range requirements {
		item := BinaryStatus{BinaryRequirement: requirement}
		if path, err := exec.LookPath(requirement.Binary); err == nil {
			item.Available = true
			item.Path = path
		} else {
			allPresent = false
		}
		status.Tools = append(status.Tools, item)
	}
	status.Ready = status.Kali && allPresent
	if !status.Ready {
		status.Instruction = "run `make dev` and reopen the repository in the Dev Container"
	}
	return status
}

// RequireKaliForActive fails with the exact recovery command outside Kali.
func RequireKaliForActive() error {
	if !inKali() {
		return ErrKaliRuntimeRequired
	}
	return nil
}

// BinaryHasCapabilities reports whether the current user is root or a Linux
// executable carries every requested file capability.
func BinaryHasCapabilities(binary string, required ...string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return false
	}
	output, err := exec.Command("getcap", path).Output()
	if err != nil {
		return false
	}
	value := strings.ToLower(string(output))
	for _, capability := range required {
		if !strings.Contains(value, strings.ToLower(capability)) {
			return false
		}
	}
	return true
}

func inKali() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "ID=kali" || strings.TrimSpace(line) == `ID="kali"` {
			return true
		}
	}
	return false
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	return err == nil && (strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd"))
}
