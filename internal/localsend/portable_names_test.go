package localsend

import "testing"

func TestPortableTransferNames(t *testing.T) {
 for _, name := range []string{
  "photo:stream.jpg", "data*backup.txt", "question?.txt",
  "quote\".txt", "bracket<1>.txt", "pipe|log.txt",
  "trailing.", "trailing ",
 } {
  if err := safeName(name); err == nil {
   t.Errorf("unsafe cross-platform name allowed: %q", name)
  }
 }
 for _, name := range []string{
  "holiday photo.jpeg", "notes_2026.txt", "family.archive.zip",
 } {
  if err := safeName(name); err != nil {
   t.Errorf("safe name rejected: %q: %v", name, err)
  }
 }
}
