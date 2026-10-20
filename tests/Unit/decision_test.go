package unit_test

import (
	"go/ast"
	"reflect"
	"regexp"
	"testing"
	"time"

	emrtd "github.com/hyz-is/arandu-emrtd"
)

// TestNothingHereDecides holds the rule this package exists under: it answers
// evidence, and whether a document is accepted is the application's decision.
//
// A type, a function or a field carrying a verdict -- Approved, Genuine,
// IsAuthentic, Fraud, Overall -- is a decision with this package's name on
// it, and the names are what an assistant reaches for first, which is why they
// are refused by name. "Check", "Examine" and the four outcomes are the
// vocabulary of evidence and stay.
func TestNothingHereDecides(t *testing.T) {
	t.Parallel()

	verdict := regexp.MustCompile(`(?i)(approv|reject|accept|verdict|decision|decide|genuine|fraud|trustworth|isvalid|overall|authentic$|isauthentic)`)
	for _, source := range productionGoFiles(t, packageRoot(t)) {
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.FuncDecl:
				if node.Name.IsExported() && verdict.MatchString(node.Name.Name) {
					t.Errorf("%s declares %s, a name that decides", source.path, node.Name.Name)
				}
			case *ast.TypeSpec:
				if node.Name.IsExported() && verdict.MatchString(node.Name.Name) {
					t.Errorf("%s declares the type %s, a name that decides", source.path, node.Name.Name)
				}
				if st, ok := node.Type.(*ast.StructType); ok {
					for _, field := range st.Fields.List {
						for _, name := range field.Names {
							if name.IsExported() && verdict.MatchString(name.Name) {
								t.Errorf("%s: %s.%s is a verdict field", source.path, node.Name.Name, name.Name)
							}
						}
					}
				}
			}
			return true
		})
	}
}

// TestTheReportHoldsNoBoolean holds the stricter rule for what an examination
// answers: outcomes, reasons and parsed values, and no boolean anywhere a
// reader of the Report can reach, because a boolean in evidence is a decision
// whatever it is called.
func TestTheReportHoldsNoBoolean(t *testing.T) {
	t.Parallel()

	for name, typ := range map[string]reflect.Type{
		"Report":     reflect.TypeOf(emrtd.Report{}),
		"MasterList": reflect.TypeOf(emrtd.MasterList{}),
	} {
		noBoolean(t, name, typ)
	}
}

// TestOnlyFourOutcomesExist keeps the outcome vocabulary closed.
func TestOnlyFourOutcomesExist(t *testing.T) {
	t.Parallel()
	got := []emrtd.Outcome{emrtd.OutcomePassed, emrtd.OutcomeFailed, emrtd.OutcomeNotPresent, emrtd.OutcomeUnverifiable}
	want := []string{"passed", "failed", "not_present", "unverifiable"}
	for i := range got {
		if string(got[i]) != want[i] {
			t.Errorf("outcome %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// noBoolean fails for every boolean reachable from typ through exported
// fields, pointers, slices, arrays and maps. time.Time is a leaf.
func noBoolean(t *testing.T, root string, typ reflect.Type) {
	t.Helper()

	timeType := reflect.TypeOf(time.Time{})
	var walk func(path string, typ reflect.Type, seen map[reflect.Type]bool)
	walk = func(path string, typ reflect.Type, seen map[reflect.Type]bool) {
		switch typ.Kind() {
		case reflect.Bool:
			t.Errorf("%s is a boolean", path)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(path+"[]", typ.Elem(), seen)
		case reflect.Map:
			walk(path+"[key]", typ.Key(), seen)
			walk(path+"[]", typ.Elem(), seen)
		case reflect.Struct:
			if typ == timeType || seen[typ] {
				return
			}
			seen[typ] = true
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if f.IsExported() {
					walk(path+"."+f.Name, f.Type, seen)
				}
			}
		}
	}
	walk(root, typ, map[reflect.Type]bool{})
}
