package secret_test

import (
	"testing"

	"github.com/macrat/lauth/secret"
)

func TestGenerate(t *testing.T) {
	for i := 0; i < 10; i++ {
		s, err := secret.Generate()
		if err != nil {
			t.Errorf("failed to generate secret: %s", err)
			continue
		}

		if len(s.Secret) != secret.LENGTH {
			t.Errorf("expected secret length is %d but got %d", secret.LENGTH, len(s.Secret))
		}
		if err := secret.Compare(string(s.Hash), string(s.Secret)); err != nil {
			t.Errorf("failed to compare generated hash and secret: %s", err)
		}
	}
}
