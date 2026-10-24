package protocol

import "time"

// Messages of the panel's Identity API (ADR 0003). Panel calls carry a
// session cookie; requests that change something must be JSON.

// InviteToken names an Invite. Tokens travel in bodies, never in URLs.
type InviteToken struct {
	Token string `json:"token"`
}

// InviteInfo is what an Invite offers, shown before it is accepted.
type InviteInfo struct {
	Kind      string    `json:"kind"`             // "new" or "recovery"
	Handle    string    `json:"handle,omitempty"` // the User a recovery Invite is for
	Admin     bool      `json:"admin"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AcceptInvite redeems an Invite. Handle is chosen on a new-User Invite and
// ignored on a recovery one.
type AcceptInvite struct {
	Token    string `json:"token"`
	Handle   string `json:"handle,omitempty"`
	Password string `json:"password"`
}

// Login starts a session. TOTPCode is required when the User has TOTP on.
type Login struct {
	Handle   string `json:"handle"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// Me is the signed-in User.
type Me struct {
	ID          string `json:"id"`
	Handle      string `json:"handle"`
	Admin       bool   `json:"admin"`
	TOTPEnabled bool   `json:"totp_enabled"`
	// MFA is set when this session proved a second factor; Admin actions
	// need it.
	MFA         bool `json:"mfa"`
	DeviceCap   int  `json:"device_cap"`
	DeviceCount int  `json:"device_count"`
}

// ChangePassword replaces the signed-in User's password.
type ChangePassword struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// TOTPOffer is a TOTP secret to scan, in force once confirmed.
type TOTPOffer struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// TOTPCode proves a TOTP code.
type TOTPCode struct {
	Code string `json:"code"`
}

// NewDevice creates a Device from a public key made in the browser; the
// private key never leaves it (ADR 0003).
type NewDevice struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// DeviceInfo is a Device as its owner and Admins see it.
type DeviceInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
	// State is the effective state: active, blocked or throttled.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Rate   uint64 `json:"rate,omitempty"` // when throttled: bytes per second
	// RecentBytes is what the Device moved in this hour and the last: the
	// "used in the last hour" mark. Never connection times (ADR 0003).
	RecentBytes uint64 `json:"recent_bytes"`
}

// DeviceUsage is a Device's usage: hourly and daily as ADR 0003 keeps
// them, and its total in the owner's current Quota Period (ADR 0010).
type DeviceUsage struct {
	Hourly []UsageRow `json:"hourly"` // the last 7 days, per Exit
	Daily  []UsageRow `json:"daily"`  // the last 90 days, per Exit
	Period UsageRow   `json:"period"` // the current Quota Period, all Exits together
}

// UsageRow is bytes in one period through one Exit.
type UsageRow struct {
	Period string `json:"period"` // an RFC 3339 hour, or a YYYY-MM-DD day or Quota Period start
	Exit   string `json:"exit,omitempty"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
}

// IssuedDevice is a new Device and everything its configs need, except the
// private key, which only the browser has.
type IssuedDevice struct {
	Device DeviceInfo   `json:"device"`
	Config DeviceConfig `json:"config"`
}

// DeviceConfig is what a Device's one config needs (ADR 0011).
type DeviceConfig struct {
	Address         string   `json:"address"`          // the Device's /32
	IPv6Placeholder string   `json:"ipv6_placeholder"` // a ULA /128, so apps drop IPv6 inside the tunnel
	DNS             string   `json:"dns"`
	BridgePublicKey string   `json:"bridge_public_key"`
	AllowedIPs      []string `json:"allowed_ips"`
	Endpoint        Endpoint `json:"endpoint"`
}

// Endpoint is where the config reaches a Bridge: the Bridge Address.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// CreateInvite asks for a new-User Invite. It may preset the User's
// Quota, what happens when they run out, and Refills to hold (ADR 0010).
type CreateInvite struct {
	Admin     bool    `json:"admin,omitempty"`
	DeviceCap int     `json:"device_cap,omitempty"` // 0: the default of 3
	Quota     *uint64 `json:"quota,omitempty"`      // bytes per Quota Period; null is unlimited, the default
	// RunningOut defaults to block; slow needs a Rate in bytes per second.
	RunningOut RunningOut `json:"running_out,omitempty"`
	Rate       uint64     `json:"rate,omitempty"`
	Refills    int        `json:"refills,omitempty"` // how many to hold, 0 to 100
	// RefillDays is how long each Refill lasts, counted from registration;
	// 0 is the default of 30.
	RefillDays int `json:"refill_days,omitempty"`
}

// IssuedInvite is an Invite to hand over out of band.
type IssuedInvite struct {
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// UserInfo is a User as Admins see them.
type UserInfo struct {
	ID          string `json:"id"`
	Handle      string `json:"handle"`
	Admin       bool   `json:"admin"`
	Suspended   bool   `json:"suspended"`
	TOTPEnabled bool   `json:"totp_enabled"`
	DeviceCap   int    `json:"device_cap"`
	DeviceCount int    `json:"device_count"`
	// PeriodBytes is the User's Usage in their current Quota Period, revoked
	// Devices included (ADR 0010): Admins see totals per User, not per
	// Device.
	PeriodBytes uint64 `json:"period_bytes"`
	// PeriodRemedies is the bytes this period's Top-ups and Resets added,
	// redeemed Refills included: the User may use Quota + PeriodRemedies.
	PeriodRemedies uint64 `json:"period_remedies"`
	// Quota is the bytes, up and down together, the User may move in one
	// Quota Period; null is unlimited.
	Quota      *uint64    `json:"quota"`
	RenewalDay int        `json:"renewal_day"` // the day of the month their Quota Periods start, 1–31
	RenewsAt   time.Time  `json:"renews_at"`   // when the current Quota Period ends and the next starts
	RunningOut RunningOut `json:"running_out"`
	Rate       uint64     `json:"rate,omitempty"` // when slow: bytes per second
	Refills    int        `json:"refills"`        // Refills held: not redeemed and not expired
}

// RunningOut is what happens to a User's Devices once they have used up
// their Quota (ADR 0010).
type RunningOut string

const (
	RunningOutBlock RunningOut = "block" // the default
	RunningOutSlow  RunningOut = "slow"  // throttled to a rate
)

// SetQuota replaces a User's Quota and what happens when they run out.
type SetQuota struct {
	Quota      *uint64    `json:"quota"` // bytes per Quota Period; null is unlimited
	RunningOut RunningOut `json:"running_out"`
	// Rate is what slow throttles each Device to, in bytes per second of
	// inner traffic each way, as Bridges enforce it.
	Rate uint64 `json:"rate,omitempty"`
}

// SetDeviceCap changes a User's Device cap.
type SetDeviceCap struct {
	DeviceCap int `json:"device_cap"`
}

// TopUp adds bytes to what a User may still use in their current Quota
// Period only (ADR 0010).
type TopUp struct {
	Bytes uint64 `json:"bytes"`
}

// GiveRefills gives a User Refills to hold and redeem themselves.
type GiveRefills struct {
	Count int `json:"count"` // 1 to 100
	// Days is how long each lasts from now; 0 is the default of 30.
	Days int `json:"days,omitempty"`
}

// MyUsage is the signed-in User's Usage and Quota (ADR 0010).
type MyUsage struct {
	Quota      *uint64     `json:"quota"` // bytes per Quota Period; null is unlimited
	RunningOut RunningOut  `json:"running_out"`
	Rate       uint64      `json:"rate,omitempty"` // when slow: bytes per second
	Current    PeriodUsage `json:"current"`        // the current Quota Period
	// Left is what the User may still use this period: the Quota, plus its
	// Top-ups and Resets, minus its Usage. Null when unlimited.
	Left *uint64 `json:"left"`
	// RenewsAt is the next Renewal Day, when the next Quota Period starts.
	RenewsAt time.Time `json:"renews_at"`
	// History is every closed Quota Period, newest first.
	History []PeriodUsage `json:"history"`
	// Refills are those held: not redeemed and not expired, soonest first.
	Refills []Refill `json:"refills"`
	// RefillAdds is what redeeming a Refill would add now; null when
	// unlimited, since then none can be redeemed.
	RefillAdds *uint64 `json:"refill_adds"`
}

// PeriodUsage is a User's Usage in one Quota Period, revoked Devices
// included, with the remedies that raised what they could use in it.
type PeriodUsage struct {
	Start    time.Time `json:"start"` // 00:00 UTC on the Renewal Day
	End      time.Time `json:"end"`   // the next period's start
	Bytes    uint64    `json:"bytes"`
	Remedies []Remedy  `json:"remedies"`
	// Detailed periods, those that started within the last 90 days, split
	// their Usage into live Devices plus one total for all Revoked Devices.
	Detailed bool                `json:"detailed"`
	Devices  []DevicePeriodUsage `json:"devices,omitempty"`
	Revoked  uint64              `json:"revoked"`
}

// DevicePeriodUsage is one live Device's Usage in a Quota Period.
type DevicePeriodUsage struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
}

// Remedy is a Top-up or a Reset recorded in a Quota Period.
type Remedy struct {
	Kind  string    `json:"kind"` // "top-up" or "reset"
	Bytes uint64    `json:"bytes"`
	At    time.Time `json:"at"`
}

// Refill is a Reset a User holds until they redeem it or it expires.
type Refill struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"` // redeemable up to and including this moment
}
