/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

package common

const (
	RansomModule                   = "ransomware"
	RansomDecoy                    = "wannacry_decoy"
	RansomWhite                    = "wannacry_white"
	RansomFileName                 = "name"
	RansomReleaseAppInFileOpenType = "file_open_release"
	RansomActionKill               = uint32(1)
	RansomActionNotKill            = uint32(2)
	RansomActionTemp               = uint32(3)
)

// zhenpeng add
const (
	// SecLogChannelSize how many event the channel can hold
	SecLogChannelSize = 1 << 13 //8192
)

type Events struct {
	//timestamp int64

	PID      uint32
	PPID     uint32
	UID      uint32
	ModuleID uint32
	EventID  uint32

	Path   [256]byte
	Source [256]byte

	Comm [16]byte
}
