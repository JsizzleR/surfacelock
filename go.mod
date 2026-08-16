module github.com/JsizzleR/surfacelock

go 1.26

require github.com/gowebpki/jcs v1.0.1

// v0.1.0 named the author's own self-hosted runtime in the conformance corpus —
// target names, capture filenames, and one server-advertised serverInfo.name.
// v0.2.0 de-identifies all of it; the verdicts are unchanged, and the redaction
// is disclosed in conformance/PREDICATES.md. Nothing about v0.1.0 is unsafe to
// run, so this is a withdrawal, not a security advisory: retracting it keeps
// `go get` from ever selecting it and hides it on pkg.go.dev.
retract v0.1.0
