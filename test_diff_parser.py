"""Unit test: diff parser only (no Joern required)."""
import sys
sys.path.insert(0, '/home/claude')
from pipeline.find_candidates import parse_modified_lines

# Case 1: a mixed hunk with both removals and additions
diff1 = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -10,6 +10,7 @@ void foo() {
     int x = 0;
     int y = 1;
-    memcpy(dst, src, len);
+    if (len > MAX) return;
+    memcpy(dst, src, len);
     return;
 }
"""
r1 = parse_modified_lines(diff1)
print("Case 1 (mixed hunk):")
print(" ", r1)
assert r1["foo.c"]["vulnerable"] == [12], r1  # the removed memcpy on old line 12
assert r1["foo.c"]["fixed"] == [12, 13], r1   # the two added lines on new 12, 13

# Case 2: pure-addition hunk (added a bounds check, removed nothing)
diff2 = """diff --git a/bar.c b/bar.c
--- a/bar.c
+++ b/bar.c
@@ -5,3 +5,4 @@ void bar(int n) {
     int buf[100];
+    if (n > 100) return;
     buf[n] = 0;
 }
"""
r2 = parse_modified_lines(diff2)
print("Case 2 (pure addition):")
print(" ", r2)
assert r2["bar.c"]["fixed"] == [6], r2
# Vulnerable side should have the context lines of this additive hunk
assert r2["bar.c"]["vulnerable"], "pure-addition case should still populate vulnerable context"
print("  vuln context picked up:", r2["bar.c"]["vulnerable"])

# Case 3: new file (--- /dev/null)
diff3 = """diff --git a/new.c b/new.c
--- /dev/null
+++ b/new.c
@@ -0,0 +1,3 @@
+void f() {}
+int x;
+int y;
"""
r3 = parse_modified_lines(diff3)
print("Case 3 (new file):")
print(" ", r3)
assert r3["new.c"]["fixed"] == [1, 2, 3], r3

# Case 4: multiple files in one diff
diff4 = diff1 + """diff --git a/baz.c b/baz.c
--- a/baz.c
+++ b/baz.c
@@ -100,2 +100,2 @@
-    old_line();
+    new_line();
     keep();
"""
r4 = parse_modified_lines(diff4)
print("Case 4 (two files):")
print(" ", r4)
assert set(r4.keys()) == {"foo.c", "baz.c"}, r4
assert r4["baz.c"]["vulnerable"] == [100]
assert r4["baz.c"]["fixed"] == [100]

# Case 5: the smoke-test pattern — pure-addition hunk adds content inside
# one function; hunk context spills into the neighboring function above it.
# The old buggy behavior grabbed all context including line 7 (the closing
# `}` of copy_bytes), leading to copy_bytes being mis-identified as a patch
# function. The fix keeps only context within 2 lines of a '+' line.
diff5 = """diff --git a/parser.c b/parser.c
--- a/parser.c
+++ b/parser.c
@@ -7,7 +7,9 @@ void copy_bytes(...) {
     memcpy(dst, src, len);
 }
 
 int parse_header(...) {
     int declared_len;
+    if (input_len < 1) return -1;
     declared_len = input[0];
     return declared_len;
 }
"""
r5 = parse_modified_lines(diff5)
print("Case 5 (pure addition inside function, hunk touches neighbor):")
print(" ", r5)
# The '+' is at new-line 12, which maps to old-line 11 (one fewer because
# of the 1 addition before it). Adjacent old-side context within window=2:
# - 2 lines before old-line 11: old-lines 9, 10 (the function header + "int declared_len")
# - 2 lines after:              old-lines 11, 12 (declared_len =, return)
# Critically, line 7 ("}") and line 8 (blank) are NOT within 2 lines of the '+',
# so they should NOT appear in vulnerable.
vuln_lines = r5["parser.c"]["vulnerable"]
assert 7 not in vuln_lines, f"line 7 (closing }} of copy_bytes) leaked: {vuln_lines}"
assert 8 not in vuln_lines, f"line 8 (blank between fns) leaked: {vuln_lines}"
# And parse_header's interior should be represented (at least one of 9-12).
assert any(9 <= l <= 12 for l in vuln_lines), \
    f"no parse_header lines captured: {vuln_lines}"
print(f"  ✓ lines 7, 8 correctly excluded; parse_header context: {vuln_lines}")

print("\nAll diff parser tests passed.")