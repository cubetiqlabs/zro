package node

import (
	"testing"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"golang.org/x/net/dns/dnsmessage"
)

func TestMagicDNS(t *testing.T) {
	d := &Daemon{
		cfg: &config.NodeConfig{Hostname: "Self_Box"}, dnsDomain: "zro.internal",
		overlayIPv4: "100.64.0.2", overlayIPv6: "fd00::2",
		peers: map[string]core.Node{"k": {Hostname: "web-1", OverlayIPv4: "100.64.0.3", OverlayIPv6: "fd00::3"}},
	}
	ask := func(name string, typ dnsmessage.Type) (dnsmessage.RCode, []dnsmessage.Resource) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		var m dnsmessage.Message
		if err := m.Unpack(d.answerDNS(q)); err != nil || m.ID != 7 || !m.Response {
			t.Fatalf("%s: bad reply %v %+v", name, err, m.Header)
		}
		return m.RCode, m.Answers
	}

	rc, ans := ask("WEB-1.zro.internal.", dnsmessage.TypeA)
	if rc != dnsmessage.RCodeSuccess || len(ans) != 1 || ans[0].Body.(*dnsmessage.AResource).A != [4]byte{100, 64, 0, 3} {
		t.Fatalf("A web-1: %v %v", rc, ans)
	}
	if rc, ans := ask("web-1.zro.internal.", dnsmessage.TypeAAAA); rc != dnsmessage.RCodeSuccess || len(ans) != 1 {
		t.Fatalf("AAAA web-1: %v %v", rc, ans)
	}
	if rc, ans := ask("self-box.zro.internal.", dnsmessage.TypeA); rc != dnsmessage.RCodeSuccess || len(ans) != 1 {
		t.Fatalf("self by label: %v %v", rc, ans)
	}
	if rc, ans := ask("web-1.zro.internal.", dnsmessage.TypeMX); rc != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatalf("MX: %v %v", rc, ans)
	}
	if rc, _ := ask("db-9.zro.internal.", dnsmessage.TypeA); rc != dnsmessage.RCodeNameError {
		t.Fatalf("unknown host: %v", rc)
	}
	if rc, _ := ask("example.com.", dnsmessage.TypeA); rc != dnsmessage.RCodeRefused {
		t.Fatalf("foreign name: %v", rc)
	}
	if rc, _ := ask("a.web-1.zro.internal.", dnsmessage.TypeA); rc != dnsmessage.RCodeRefused {
		t.Fatalf("sub-name: %v", rc)
	}
}
