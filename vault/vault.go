package vault

import (
	"encoding/json"
	"fmt"
	"os"
)

type Vault struct {
	Version int
	Header  Header
	Db      Db
}

type VaultEncrypted struct {
	Version int
	Header  Header
	Db      string
}

type Header struct {
	Slots  []Slot
	Params Params
}

type Slot struct {
	Type      int
	Uuid      string
	Key       string
	KeyParams Params `json:"key_params"`
	N         int
	R         int
	P         int
	Salt      string
	Repaired  bool
	IsBackup  bool `json:"is_backup"`
}

type Params struct {
	Nonce string
	Tag   string
}

type Db struct {
	Version int
	Entries []Entry
	Groups  []Group
}

type Entry struct {
	Type     string
	Uuid     string
	Name     string
	Issuer   string
	Note     string
	Icon     string
	IconMime string `json:"icon_mime"`
	IconHash string `json:"icon_hash"`
	Favorite bool
	Info     Info
	Groups   []string
}

type Info struct {
	Secret  string
	Algo    string
	Digits  int
	Period  int
	Counter int
	Pin     string
}

type Group struct {
	Uuid string
	Name string
}

// ReadVaultFile parses the json file at the path
// and returns a vault.
func ReadVaultFile(filePath string) (*Vault, error) {
	var vault Vault

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &vault)

	return &vault, err
}

// ReadVaultFileEnc parses the json file at the path
// and returns an encrypted vault.
func ReadVaultFileEnc(filePath string) (*VaultEncrypted, error) {
	var vault VaultEncrypted

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &vault)

	return &vault, err
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

	var fields []interface{} = []interface{}{
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

	var fields []interface{} = []interface{}{
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

	var fields []interface{} = []interface{}{i.Secret, i.Algo, i.Digits, i.Period, i.Counter}

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
