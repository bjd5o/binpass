//go:build linux

package secretservice

import (
	"net"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePass is an in-memory PassStore, so the D-Bus layer can be driven
// without a store on disk.
type fakePass struct {
	entries map[string]string
}

func (f *fakePass) Get(name string) (*secret.Secret, error) {
	raw, ok := f.entries[name]
	if !ok {
		return nil, ErrNotFound
	}
	return secret.Parse([]byte(raw)), nil
}

func (f *fakePass) Set(name string, sec *secret.Secret) error {
	f.entries[name] = sec.String()
	return nil
}

func (f *fakePass) List(sub string) ([]string, error) {
	var out []string
	for k := range f.entries {
		if sub == "" || strings.HasPrefix(k, sub+"/") {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakePass) Remove(name string) error {
	if _, ok := f.entries[name]; !ok {
		return ErrNotFound
	}
	delete(f.entries, name)
	return nil
}

func (f *fakePass) Exists(name string) bool {
	_, ok := f.entries[name]
	return ok
}

// callerExeFor is the executable the test policy sees behind a bus name.
const callerExeFor = "/usr/bin/greedy-client"

// newPolicyService returns a provider whose bus connection is one end of a
// pipe. Exporting an object only registers it in godbus's own table, so the
// whole provider can be exercised in-process, with no session bus and
// nothing of the developer's keyring in reach.
func newPolicyService(t *testing.T, cfg Config) (*Service, *Store) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	conn, err := dbus.NewConn(client)
	require.NoError(t, err)

	store := NewStore(&fakePass{entries: map[string]string{}}, []byte("test seed"))
	engine := NewPolicyEngine(cfg, func(string) (string, error) { return callerExeFor, nil }, nil)
	return NewService(conn, store, engine), store
}

// senderMessage builds the message godbus delivers for a call from sender.
// An empty sender stands for a connection the bus did not name.
func senderMessage(sender string) dbus.Message {
	m := dbus.Message{Headers: map[dbus.HeaderField]dbus.Variant{}}
	if sender != "" {
		m.Headers[dbus.FieldSender] = dbus.MakeVariant(sender)
	}
	return m
}

// openPlainSession opens a plain-algorithm session for sender.
func openPlainSession(t *testing.T, svc *Service, _ string) dbus.ObjectPath {
	t.Helper()
	_, p, derr := svc.OpenSession(AlgPlain, dbus.MakeVariant(""))
	require.Nil(t, derr)
	return p
}

// denyCallerConfig refuses the test caller by its executable path, which is
// the only kind of rule that depends on the caller being identified at all.
func denyCallerConfig() Config {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{App: callerExeFor, Action: ActionDeny}}
	return cfg
}

// storeItem puts one item in the store and returns its object path.
func storeItem(t *testing.T, store *Store, collection, secretValue string) dbus.ObjectPath {
	t.Helper()
	it, err := store.CreateItem(collection, &Item{
		Label:      "GitHub",
		Secret:     secretValue,
		Attributes: map[string]string{"server": "github.com"},
	}, false)
	require.NoError(t, err)
	return itemObjectPath(collection, it.ID)
}

// TestGetSecretsEnforcesThePolicy covers the batch read. It handed out the
// same plaintext as Item.GetSecret while consulting the policy with an empty
// caller, so every app: rule — the only configurable authorisation the
// provider has — was bypassed by asking for the secret this way instead.
func TestGetSecretsEnforcesThePolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		sender  string
		wantErr bool
		want    string
	}{
		{
			name:   "an app: deny rule blocks the batch path too",
			cfg:    denyCallerConfig(),
			sender: ":1.7",
			want:   "",
		},
		{
			name:   "an allowed caller still gets its secret",
			cfg:    DefaultConfig(),
			sender: ":1.7",
			want:   "hunter2",
		},
		{
			name:    "a caller the bus did not name is refused outright",
			cfg:     DefaultConfig(),
			sender:  "",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, store := newPolicyService(t, tc.cfg)
			item := storeItem(t, store, "login", "hunter2")
			sess := openPlainSession(t, svc, tc.sender)

			out, derr := svc.GetSecrets(senderMessage(tc.sender), []dbus.ObjectPath{item}, sess)
			if tc.wantErr {
				assert.NotNil(t, derr, "an unidentified caller must be refused, not served")
				assert.Empty(t, out)
				return
			}
			require.Nil(t, derr)
			if tc.want == "" {
				assert.Empty(t, out, "a denied item must not appear in the reply")
				return
			}
			require.Len(t, out, 1)
			assert.Equal(t, tc.want, string(out[item].Value))
		})
	}
}
