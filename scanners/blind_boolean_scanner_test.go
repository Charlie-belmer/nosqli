package scanners_test

import (
	"github.com/Charlie-belmer/nosqli/scanners"
	"github.com/Charlie-belmer/nosqli/scanutil"
	"testing"
)


func setup(t *testing.T, body string) scanutil.AttackObject {
	testurl := "http://www.test.com/"
	var scanOptions = scanutil.ScanOptions{Target: testurl}

	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Did not create attack object successfully")
	}
	att.SetBody(body)
	return att
}