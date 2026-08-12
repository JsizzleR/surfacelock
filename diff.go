package surfacelock

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// Class is a drift severity class (SPEC.md §8), most severe first.
type Class int

const (
	ClassDescription Class = iota // prompt text changed — the injection vector
	ClassSchema                   // machine-consumed contract changed
	ClassEra                      // negotiated protocol revision changed
	ClassMetadata                 // other change to an existing tool
	ClassRemoved                  // tool gone
	ClassAdded                    // tool appeared (still drift: new prompt text)
)

func (c Class) String() string {
	switch c {
	case ClassDescription:
		return "description"
	case ClassSchema:
		return "schema"
	case ClassEra:
		return "era"
	case ClassMetadata:
		return "metadata"
	case ClassRemoved:
		return "removed"
	case ClassAdded:
		return "added"
	}
	return fmt.Sprintf("class(%d)", int(c))
}

// ToolDiff is the classified drift of one tool. Classes is sorted most severe first
// and never empty.
type ToolDiff struct {
	Name    string
	Classes []Class
}

// Severity is the most severe class carried by this tool's drift.
func (d ToolDiff) Severity() Class { return d.Classes[0] }

// SurfaceDiff is the classified drift between a locked entry and a live surface.
type SurfaceDiff struct {
	EraChanged          bool
	OldEra, NewEra      string
	InstructionsChanged bool // classified as description: instructions are prompt text
	Tools               []ToolDiff
}

// Empty reports whether nothing drifted.
func (d *SurfaceDiff) Empty() bool {
	return !d.EraChanged && !d.InstructionsChanged && len(d.Tools) == 0
}

// Severity is the most severe class present in the whole diff.
func (d *SurfaceDiff) Severity() Class {
	sev := ClassAdded + 1
	if d.InstructionsChanged {
		sev = ClassDescription
	}
	if d.EraChanged && ClassEra < sev {
		sev = ClassEra
	}
	for _, t := range d.Tools {
		if t.Severity() < sev {
			sev = t.Severity()
		}
	}
	return sev
}

// Diff classifies the drift between a locked entry and an admitted live surface.
// The entry must have passed Validate: classification trusts the stored content.
func Diff(old *ServerLock, live *Surface) (*SurfaceDiff, error) {
	d := &SurfaceDiff{OldEra: old.Protocol.Era, NewEra: live.Era}
	d.EraChanged = old.Protocol.Era != live.Era
	d.InstructionsChanged = old.HInstr != live.HInstr

	oldByName := make(map[string]*ToolLock, len(old.Tools))
	for i := range old.Tools {
		oldByName[old.Tools[i].Name] = &old.Tools[i]
	}
	liveByName := make(map[string]*Tool, len(live.Tools))
	for i := range live.Tools {
		liveByName[live.Tools[i].Name] = &live.Tools[i]
	}

	for name, ot := range oldByName {
		lt, ok := liveByName[name]
		if !ok {
			d.Tools = append(d.Tools, ToolDiff{Name: name, Classes: []Class{ClassRemoved}})
			continue
		}
		if ot.HTool == lt.HTool {
			continue
		}
		classes, err := classifyToolDrift(ot.Tool, lt.Canon)
		if err != nil {
			return nil, err
		}
		d.Tools = append(d.Tools, ToolDiff{Name: name, Classes: classes})
	}
	for name := range liveByName {
		if _, ok := oldByName[name]; !ok {
			d.Tools = append(d.Tools, ToolDiff{Name: name, Classes: []Class{ClassAdded}})
		}
	}

	sort.Slice(d.Tools, func(i, j int) bool {
		if d.Tools[i].Severity() != d.Tools[j].Severity() {
			return d.Tools[i].Severity() < d.Tools[j].Severity()
		}
		return d.Tools[i].Name < d.Tools[j].Name
	})
	return d, nil
}

// classifyToolDrift attributes the drift between two versions of the same tool.
// h_tool already differs; the result is every class that applies, most severe first.
func classifyToolDrift(oldRaw, newRaw json.RawMessage) ([]Class, error) {
	var oldV, newV any
	if err := json.Unmarshal(oldRaw, &oldV); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(newRaw, &newV); err != nil {
		return nil, err
	}
	var classes []Class

	// description: any string value whose object key is "description", anywhere in
	// the tool object — schemas embed per-property descriptions, and an attacker who
	// moves injection text into a property description must not earn a milder class.
	if !reflect.DeepEqual(collectDescriptions(oldV), collectDescriptions(newV)) {
		classes = append(classes, ClassDescription)
	}

	// schema: the machine-consumed contract — inputSchema/outputSchema net of the
	// description strings already counted above, plus annotations (hints like
	// readOnlyHint steer client confirmation behavior).
	oldObj, _ := oldV.(map[string]any)
	newObj, _ := newV.(map[string]any)
	schemaChanged := false
	for _, key := range []string{"inputSchema", "outputSchema"} {
		if !reflect.DeepEqual(stripDescriptions(oldObj[key]), stripDescriptions(newObj[key])) {
			schemaChanged = true
		}
	}
	if !reflect.DeepEqual(oldObj["annotations"], newObj["annotations"]) {
		schemaChanged = true
	}
	if schemaChanged {
		classes = append(classes, ClassSchema)
	}

	// metadata: anything left after the fields above are excluded.
	if !reflect.DeepEqual(residual(oldObj), residual(newObj)) {
		classes = append(classes, ClassMetadata)
	}

	if len(classes) == 0 {
		// h_tool differs but every projection agrees — should be unreachable, but a
		// classifier must never report "no drift" for differing hashes.
		classes = append(classes, ClassMetadata)
	}
	return classes, nil
}

// collectDescriptions gathers every string value held under a "description" object
// key, keyed by its path, recursing through objects and arrays.
func collectDescriptions(v any) map[string]string {
	out := map[string]string{}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch t := v.(type) {
		case map[string]any:
			for k, mv := range t {
				p := path + "/" + k
				if k == "description" {
					if s, ok := mv.(string); ok {
						out[p] = s
						continue
					}
				}
				walk(mv, p)
			}
		case []any:
			for i, e := range t {
				walk(e, fmt.Sprintf("%s/%d", path, i))
			}
		}
	}
	walk(v, "")
	return out
}

// stripDescriptions returns a copy of v with every string-valued "description"
// member removed, so schema comparison excludes what the description class counts.
func stripDescriptions(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, mv := range t {
			if k == "description" {
				if _, ok := mv.(string); ok {
					continue
				}
			}
			out[k] = stripDescriptions(mv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = stripDescriptions(e)
		}
		return out
	default:
		return v
	}
}

// residual returns the tool object minus the fields the description and schema
// classes already cover: description strings anywhere, inputSchema, outputSchema,
// annotations. What remains is title and fields this spec has never heard of.
func residual(obj map[string]any) any {
	if obj == nil {
		return nil
	}
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		switch k {
		case "inputSchema", "outputSchema", "annotations":
			continue
		}
		out[k] = v
	}
	return stripDescriptions(out)
}
