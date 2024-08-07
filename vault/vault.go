// Package vault provides functionality for interacting with
// Aegis Authenticator vault data.
package vault

import (
	"fmt"
)

type Vault struct {
	Version int    `json:"version"`
	Header  Header `json:"header"`
	Db      Db     `json:"db"`
}

type VaultEncrypted struct {
	Version int    `json:"version"`
	Header  Header `json:"header"`
	Db      string `json:"db"`
}

type Header struct {
	Slots  []Slot `json:"slots"`
	Params Params `json:"params"`
}

type Slot struct {
	Type      int    `json:"type"`
	Uuid      string `json:"uuid"`
	Key       string `json:"key"`
	KeyParams Params `json:"key_params"`
	N         int    `json:"n"`
	R         int    `json:"r"`
	P         int    `json:"p"`
	Salt      string `json:"salt"`
	Repaired  bool   `json:"repaired"`
	IsBackup  bool   `json:"is_backup"`
}

type Params struct {
	Nonce string `json:"nonce"`
	Tag   string `json:"tag"`
}

type Db struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
	Groups  []Group `json:"groups"`
}

type Entry struct {
	Type     string   `json:"type"`
	Uuid     string   `json:"uuid"`
	Name     string   `json:"name"`
	Issuer   string   `json:"issuer"`
	Note     string   `json:"note"`
	Icon     string   `json:"icon"`
	IconMime string   `json:"icon_mime"`
	IconHash string   `json:"icon_hash"`
	Favorite bool     `json:"favorite"`
	Info     Info     `json:"info"`
	Groups   []string `json:"groups"`
}

type Info struct {
	Secret  string `json:"secret"`
	Algo    string `json:"algo"`
	Digits  int    `json:"digits"`
	Period  int    `json:"period,omitempty"`
	Counter int    `json:"counter,omitempty"`
	Pin     string `json:"pin,omitempty"`
}

type Group struct {
	Uuid string `json:"uuid"`
	Name string `json:"name"`
}

func (v *Vault) String() string {
	return fmt.Sprintf("Vault{ version: %v, header: %v, db: %v }", v.Version, v.Header, v.Db)
}

func (v *VaultEncrypted) String() string {
	return fmt.Sprintf("Vault{ version: %v, header: %v, db: %v }", v.Version, v.Header, v.Db)
}

func (h Header) String() string {
	return fmt.Sprintf("Header{ slots: %v, params: %v }", h.Slots, h.Params)
}

func (s Slot) String() string {
	var outputFormat string = "Slot{ type: %v, uuid: %v, key: %v, keyParams: %v, "
	outputFormat += "n: %v, r: %v, p: %v, salt: %v, repaired: %v, isBackup: %v }"

	var fields []any = []any{
		s.Type,
		s.Uuid,
		s.Key,
		s.KeyParams,
		s.N,
		s.R,
		s.P,
		s.Salt,
		s.Repaired,
		s.IsBackup,
	}

	return fmt.Sprintf(outputFormat, fields...)
}

func (p Params) String() string {
	return fmt.Sprintf("Params{ nonce: %v, tag: %v }", p.Nonce, p.Tag)
}

func (d Db) String() string {
	return fmt.Sprintf("Db{ version: %v, entries: %v, groups: %v}", d.Version, d.Entries, d.Groups)
}

func (e Entry) String() string {
	var outputFormat string = "Entry{ type: %v, uuid: %v, name: %v, issuer: %v, note: %v, "
	outputFormat += "icon: %v, iconMime: %v, iconHash: %v, favorite: %v, "
	outputFormat += "info: %v, groups: %v }"

	var fields []any = []any{
		e.Type,
		e.Uuid,
		e.Name,
		e.Issuer,
		e.Note,
		e.Icon,
		e.IconMime,
		e.IconHash,
		e.Favorite,
		e.Info,
		e.Groups,
	}

	return fmt.Sprintf(outputFormat, fields...)
}

func (i Info) String() string {
	var outputFormat string = "Info{ secret: %v, algo: %v, digits: %v, period: %v, counter: %v"

	var fields []any = []any{i.Secret, i.Algo, i.Digits, i.Period, i.Counter}

	// If the pin is included, add it to the formatted output and field data
	if i.Pin != "" {
		outputFormat += "pin: %v"
		fields = append(fields, i.Pin)
	}

	outputFormat += " }"

	return fmt.Sprintf(outputFormat, fields...)
}

func (g Group) String() string {
	return fmt.Sprintf("Group{ uuid: %v, name: %v }", g.Uuid, g.Name)
}
