from ..core.registry import AnalyzerRegistry

def register_all_analyzers():
    AnalyzerRegistry.clear()

    # Generic Analyzer (Fallback)
    from ..analyzers.generic import GenericAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=GenericAnalyzer,
        name="GenericAnalyzer",
        mimes=[],
        magics=[],
        extensions=[],
        priority=0,
        is_fallback=True
    )

    # Image Analyzer
    from ..analyzers.image import ImageAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=ImageAnalyzer,
        name="ImageAnalyzer",
        mimes=["image/png", "image/jpeg", "image/gif", "image/bmp", "image/tiff", "image/webp"],
        magics=["PNG Image", "JPEG Image", "GIF Image", "BMP Image", "TIFF Image", "WebP Image"],
        extensions=["png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp"],
        priority=10
    )

    # Script Analyzer
    from ..analyzers.script import ScriptAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=ScriptAnalyzer,
        name="ScriptAnalyzer",
        mimes=["text/plain", "application/x-sh", "application/javascript", "text/x-python"],
        magics=["Shell Script", "Python Script", "Batch Script", "PowerShell Script", "VBScript"],
        extensions=["sh", "py", "bat", "cmd", "ps1", "vbs", "js"],
        priority=20
    )

    # Executable Analyzer
    from ..analyzers.executable import ExecutableAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=ExecutableAnalyzer,
        name="ExecutableAnalyzer",
        mimes=["application/x-dosexec", "application/x-executable", "application/x-mach-binary"],
        magics=["PE Executable", "ELF Executable", "Mach-O Executable"],
        extensions=["exe", "dll", "sys", "elf", "bin", "so"],
        priority=30
    )

    # Office Analyzer
    from ..analyzers.office import OfficeAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=OfficeAnalyzer,
        name="OfficeAnalyzer",
        mimes=["application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
               "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
               "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
        magics=["OLE Office Document", "OOXML Document"],
        extensions=["doc", "xls", "ppt", "docx", "xlsx", "pptx"],
        priority=40
    )

    # PDF Analyzer
    from ..analyzers.pdf import PDFAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=PDFAnalyzer,
        name="PDFAnalyzer",
        mimes=["application/pdf"],
        magics=["PDF Document"],
        extensions=["pdf"],
        priority=50
    )

    # Archive Analyzer
    from ..analyzers.archive import ArchiveAnalyzer
    AnalyzerRegistry.register(
        analyzer_cls=ArchiveAnalyzer,
        name="ArchiveAnalyzer",
        mimes=["application/zip", "application/x-tar", "application/gzip", "application/x-bzip2"],
        magics=["ZIP Archive", "TAR Archive", "GZIP Archive", "BZIP2 Archive"],
        extensions=["zip", "tar", "gz", "bz2"],
        priority=60
    )
