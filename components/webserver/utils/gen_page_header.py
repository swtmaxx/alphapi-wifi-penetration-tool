import gzip, io, sys, os

src = sys.argv[1]
dst = sys.argv[2]
name = sys.argv[3]           # e.g. page_index
guard = name.upper() + "_H"

with open(src, "rb") as f:
    raw = f.read()

# mtime=0 keeps output reproducible
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
    gz.write(raw)
data = buf.getvalue()

lines = []
lines.append("#ifndef %s" % guard)
lines.append("#define %s" % guard)
lines.append("")
lines.append("// This file was generated from utils/%s using gzip and xxd-compatible formatting." % os.path.basename(src))
lines.append("unsigned char %s[] = {" % name)
per = 12
for i in range(0, len(data), per):
    chunk = data[i:i+per]
    lines.append("  " + ", ".join("0X%02X" % b for b in chunk) + ",")
lines.append("};")
lines.append("unsigned int %s_len = %d;" % (name, len(data)))
lines.append("")
lines.append("#endif")

with open(dst, "w", newline="\n") as f:
    f.write("\n".join(lines) + "\n")

print("generated %s: %d bytes gz, %d lines" % (dst, len(data), len(lines)))