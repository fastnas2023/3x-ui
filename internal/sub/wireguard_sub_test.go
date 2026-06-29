package sub

import (
	"net/url"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestGetSubsIncludesWireGuardPeerForClient(t *testing.T) {
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	const (
		subID           = "sub-wg"
		email           = "zjh"
		serverSecret    = "8DpmXSZ0/eN91i9/SfVHWoebi4PRxhttz6ANXqV/7WI="
		clientPrivate   = "aArNhwxFKK/lp1vg5DI+mjXJwsu/QQt4GhhjJ6vUcn8="
		clientPublic    = "JblmjjJ+6968XKppAQn8ma/ribueB3HVxr6Jw/LCrjY="
		clientAddress   = "10.0.0.4/32"
		subscribeHost   = "sub.example.test"
		wireguardPort   = 33196
		wireguardRemark = "US WG"
	)

	db := database.GetDB()
	client := &model.ClientRecord{Email: email, SubID: subID, Enable: true}
	if err := db.Create(client).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}
	settings := `{
		"secretKey": "` + serverSecret + `",
		"mtu": 1400,
		"peers": [
			{
				"clientId": 999,
				"clientEmail": "other",
				"comment": "zjh",
				"privateKey": "wrong",
				"publicKey": "wrong",
				"allowedIPs": ["10.0.0.9/32"]
			},
			{
				"clientId": ` + strconv.Itoa(client.Id) + `,
				"clientEmail": "` + email + `",
				"comment": "` + email + `",
				"privateKey": "` + clientPrivate + `",
				"publicKey": "` + clientPublic + `",
				"allowedIPs": ["` + clientAddress + `"]
			}
		]
	}`
	inbound := &model.Inbound{
		UserId:       1,
		Tag:          "wg-sub",
		Remark:       wireguardRemark,
		Enable:       true,
		Port:         wireguardPort,
		Protocol:     model.WireGuard,
		Settings:     settings,
		SubSortIndex: 1,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatalf("seed client inbound: %v", err)
	}

	links, emails, _, traffic, err := NewSubService("").GetSubs(subID, subscribeHost)
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("links = %#v, want exactly one WireGuard link", links)
	}
	if len(emails) != 1 || emails[0] != email {
		t.Fatalf("emails = %#v, want %q", emails, email)
	}
	if !traffic.Enable {
		t.Fatalf("traffic.Enable = false, want true")
	}

	u, err := url.Parse(links[0])
	if err != nil {
		t.Fatalf("parse link %q: %v", links[0], err)
	}
	if u.Scheme != "wireguard" {
		t.Fatalf("scheme = %q, want wireguard; link=%q", u.Scheme, links[0])
	}
	if got := u.User.Username(); got != clientPrivate {
		t.Fatalf("private key = %q, want zjh peer private key", got)
	}
	if got := u.Host; got != "sub.example.test:33196" {
		t.Fatalf("host = %q, want sub.example.test:33196", got)
	}
	q := u.Query()
	if got := q.Get("publickey"); got != wireGuardPublicKeyFromPrivate(serverSecret) {
		t.Fatalf("publickey = %q, want derived server public key", got)
	}
	if got := q.Get("address"); got != clientAddress {
		t.Fatalf("address = %q, want %q", got, clientAddress)
	}
	if got := q.Get("mtu"); got != "1400" {
		t.Fatalf("mtu = %q, want 1400", got)
	}
	if got := u.Fragment; got != wireguardRemark+"-"+email {
		t.Fatalf("fragment = %q, want %q", got, wireguardRemark+"-"+email)
	}
}
