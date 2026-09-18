# 平台下发的 Zeek 站点策略：在分析 PCAP 时随本地策略一起加载。
# 由 ZeekAdapter 通过 runner 传给 zeek 二进制（见 app/integrations/zeek/runner.py）。

@load base/protocols/dns
@load base/protocols/http
@load base/frameworks/notice

module DST;
export {
    redef enum Notice::Type += {
        Long_DNS_Query,
        Sensitive_URI,
        Scanner_User_Agent
    };
}

# 长域名查询（隧道/编码域名特征）与超长 TXT 记录。
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| >= 40 )
        NOTICE([$note=DST::Long_DNS_Query, $msg="Long DNS query", $conn=c]);
    }

# 明文凭据外发（简化判定：URL 中出现口令类参数）。
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( /password|passwd|pwd|token/ in unescaped_URI )
        NOTICE([$note=DST::Sensitive_URI, $msg="Credential parameter in HTTP URI", $conn=c]);
    }

# 疑似扫描器的 User-Agent。
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "USER-AGENT" && /sqlmap|nikto|nmap|masscan/ in value )
        NOTICE([$note=DST::Scanner_User_Agent, $msg="Scanner User-Agent", $conn=c]);
    }
