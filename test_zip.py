import io, zipfile
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    info = zipfile.ZipInfo("huge.txt")
    info.file_size = 1000 * 1024 * 1024
    info.compress_size = 100
    zf.writestr(info, b"x"*100)
    
with zipfile.ZipFile(io.BytesIO(buf.getvalue()), "r") as zf:
    for info in zf.infolist():
        print(info.file_size, info.compress_size)
