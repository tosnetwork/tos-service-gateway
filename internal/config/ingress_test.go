package config

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-gateway/internal/ingress"
)

func clearIngressEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"TOS_SERVICE_INGRESS_GLOBAL_CONCURRENT", "TOS_SERVICE_INGRESS_CLIENT_CONCURRENT",
		"TOS_SERVICE_INGRESS_CLIENT_REQUESTS_PER_MINUTE", "TOS_SERVICE_CLIENT_ADDRESS_HEADER"} {
		t.Setenv(name, "")
	}
}

func TestIngressLimitsDefaultToTheIngressDefaults(t *testing.T) {
	clearIngressEnv(t)
	limits, err := ingressLimitsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if limits != ingress.DefaultLimits() {
		t.Fatalf("limits = %+v, want defaults %+v", limits, ingress.DefaultLimits())
	}
}

func TestIngressLimitsOverrides(t *testing.T) {
	clearIngressEnv(t)
	t.Setenv("TOS_SERVICE_INGRESS_GLOBAL_CONCURRENT", "200")
	t.Setenv("TOS_SERVICE_INGRESS_CLIENT_CONCURRENT", "20")
	t.Setenv("TOS_SERVICE_INGRESS_CLIENT_REQUESTS_PER_MINUTE", "1200")
	t.Setenv("TOS_SERVICE_CLIENT_ADDRESS_HEADER", ingress.HeaderCFConnectingIP)
	limits, err := ingressLimitsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if limits.GlobalConcurrent != 200 || limits.ClientConcurrent != 20 || limits.ClientRequestsPerWindow != 1200 ||
		limits.ClientAddressHeader != ingress.HeaderCFConnectingIP {
		t.Fatalf("overrides not applied: %+v", limits)
	}
}

func TestIngressLimitsRejectInvalidOverrides(t *testing.T) {
	cases := map[string][2]string{
		"zero global":           {"TOS_SERVICE_INGRESS_GLOBAL_CONCURRENT", "0"},
		"huge global":           {"TOS_SERVICE_INGRESS_GLOBAL_CONCURRENT", "10001"},
		"non-integer global":    {"TOS_SERVICE_INGRESS_GLOBAL_CONCURRENT", "many"},
		"zero client":           {"TOS_SERVICE_INGRESS_CLIENT_CONCURRENT", "0"},
		"client above global":   {"TOS_SERVICE_INGRESS_CLIENT_CONCURRENT", "65"},
		"zero rate":             {"TOS_SERVICE_INGRESS_CLIENT_REQUESTS_PER_MINUTE", "0"},
		"huge rate":             {"TOS_SERVICE_INGRESS_CLIENT_REQUESTS_PER_MINUTE", "1000001"},
		"unknown header":        {"TOS_SERVICE_CLIENT_ADDRESS_HEADER", "Forwarded"},
		"header with bad case":  {"TOS_SERVICE_CLIENT_ADDRESS_HEADER", "x-forwarded-for"},
		"negative client value": {"TOS_SERVICE_INGRESS_CLIENT_CONCURRENT", "-1"},
	}
	for name, setting := range cases {
		t.Run(name, func(t *testing.T) {
			clearIngressEnv(t)
			t.Setenv(setting[0], setting[1])
			limits, err := ingressLimitsFromEnv()
			if err == nil {
				t.Fatalf("accepted %s=%s as %+v", setting[0], setting[1], limits)
			}
			// The operator must be told which setting is wrong.
			if !strings.Contains(err.Error(), setting[0]) {
				t.Fatalf("error %q does not name %s", err, setting[0])
			}
		})
	}
}
