package emrtd

// DeviceStatus is what the device reports about a protocol it ran with the
// chip.
type DeviceStatus string

// The statuses a device reports.
const (
	// DeviceCompleted is a protocol the device ran to the end: for Chip
	// Authentication, secure messaging restarted under the new keys and the
	// chip answered under them.
	DeviceCompleted DeviceStatus = "completed"
	// DeviceFailed is a protocol the device started and the chip did not
	// complete.
	DeviceFailed DeviceStatus = "failed"
)

// ChipAuthenticationClaim is what the device reports about the Chip
// Authentication it ran.
//
// Chip Authentication runs between the chip and the device: an ephemeral key
// agreement with the DG14 key, then secure messaging under the keys it
// derives. A chip that answers under them holds the DG14 private key. The
// server sees none of it; what it can check is that the claim names a
// protocol and a key the chip's DG14 lists, and that DG14 itself passed
// Passive Authentication. The rest is the device's word, and the check says
// so.
type ChipAuthenticationClaim struct {
	// Protocol is the OID of the protocol the device ran, as DG14 names it
	// (id-CA-ECDH-AES-CBC-CMAC-128 and so on).
	Protocol string
	// KeyID is the key it used, or -1 when DG14 has one key.
	KeyID int64
	// Status is what the device reports.
	Status DeviceStatus
}

// ExamineChipAuthenticationClaim checks a device's Chip Authentication claim
// against DG14. dg14Hash is the outcome of DG14's data group hash check: a
// claim against a DG14 that did not pass it is unverifiable, because an
// unauthenticated DG14 can name any key.
//
// A consistent claim passes with ReasonDeviceAssertedOnly: the server checked
// the claim, and the protocol itself was run and checked on the device.
func ExamineChipAuthenticationClaim(claim *ChipAuthenticationClaim, dg14 *SecurityInfos, dg14Hash Outcome) Check {
	const name = CheckChipAuthenticationClaim
	file := FileName(14)
	if claim == nil {
		return notPresent(name, file, ReasonNotProvided, "the device reported no Chip Authentication")
	}
	if dg14 == nil {
		return notPresent(name, file, ReasonNotProvided, "no DG14 to hold the claim against")
	}
	if dg14Hash != OutcomePassed {
		return unverifiable(name, file, ReasonKeyNotAuthenticated, "DG14 did not pass Passive Authentication, so the keys it lists are not the chip's by any evidence here")
	}
	switch claim.Status {
	case DeviceCompleted:
	case DeviceFailed:
		return failed(name, file, ReasonDeviceReportedFailure, "the device reports that Chip Authentication did not complete")
	default:
		return unverifiable(name, file, ReasonUnknownDeviceStatus, "the device reported a status this package does not know")
	}
	var info *ChipAuthenticationInfo
	for i := range dg14.ChipAuthentication {
		ca := &dg14.ChipAuthentication[i]
		if ca.Protocol == claim.Protocol && (ca.KeyID == claim.KeyID || ca.KeyID == -1 || claim.KeyID == -1) {
			info = ca
			break
		}
	}
	if info == nil {
		return failed(name, file, ReasonProtocolNotInDG14, "DG14 lists no ChipAuthenticationInfo for the protocol and key the device names")
	}
	keys := 0
	for _, k := range dg14.ChipAuthenticationKeys {
		if k.KeyAgreement != info.KeyAgreement {
			continue
		}
		if claim.KeyID == -1 || k.KeyID == -1 || k.KeyID == claim.KeyID {
			keys++
		}
	}
	if keys == 0 {
		return failed(name, file, ReasonKeyNotInDG14, "DG14 holds no Chip Authentication key for the claim")
	}
	return passed(name, file, ReasonDeviceAssertedOnly,
		"the claim is consistent with the authenticated DG14; the protocol ran on the device and was not observed by the server")
}
