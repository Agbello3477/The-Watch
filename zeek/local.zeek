## ============================================================================
## THE WATCH SOC — Zeek Network Security Monitor Configuration (local.zeek)
## Passive SPAN/TAP Traffic Dissection & JSON Telemetry Output
## ============================================================================

@load base/frameworks/notice
@load base/frameworks/files
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/x509
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/frameworks/files/hash-all-files

# 1. Produce structured JSON-formatted logs with ISO-8601 timestamps
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# 2. Capture full connection state, community ID, and VLAN/MAC metadata
redef Conn::default_capture_password = F;

# 3. Enable MD5 and SHA256 file hashing across all HTTP/FTP/SMB transfers
event file_new(f: fa_file)
{
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SHA256);
}

# 4. Custom Notice Policy: Detect SQL Injection & Path Traversal in HTTP URIs
export {
    redef enum Notice::Type += {
        TheWatch_SQLi_URI_Attempt,
        TheWatch_Path_Traversal_Attempt,
        TheWatch_Suspicious_JA3_Client
    };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if ( /UNION(\s+ALL)?\s+SELECT|OR\s+1=1|information_schema/i in unescaped_URI )
    {
        NOTICE([
            $note=TheWatch_SQLi_URI_Attempt,
            $conn=c,
            $msg=fmt("Zeek HTTP Dissector: SQL Injection signature detected in URI (%s %s)", method, unescaped_URI),
            $sub="CRITICAL",
            $identifier=cat(c$id$orig_h, unescaped_URI)
        ]);
    }

    if ( /\.\.\/|\.\.\\|\/etc\/passwd/i in unescaped_URI )
    {
        NOTICE([
            $note=TheWatch_Path_Traversal_Attempt,
            $conn=c,
            $msg=fmt("Zeek HTTP Dissector: Directory traversal probe detected (%s %s)", method, unescaped_URI),
            $sub="HIGH",
            $identifier=cat(c$id$orig_h, unescaped_URI)
        ]);
    }
}
