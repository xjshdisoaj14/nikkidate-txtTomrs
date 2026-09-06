import re
import urllib.request

# 待拉取并合并的 AdGuard / ABP 规则源
SOURCES = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt"
]

def fetch_rules(url):
    """从 URL 获取文本规则内容"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"[!] 下载失败: {url}, 错误信息: {e}")
        return []

def parse_adguard_rules(lines):
    """解析并提取规则中的有效域名"""
    domain_exact = set()
    domain_suffix = set()
    domain_regex = set()

    for line in lines:
        line = line.strip()
        
        # 1. 过滤空行、注释(! 或 #)以及元素选择阻断规则(## / #@# / #?#)
        if not line or line.startswith('!') or line.startswith('#') or '##' in line or '#@#' in line or '#?#' in line:
            continue

        # 2. 剥离规则尾部的修饰符 (如 $script,image,domain=...)
        if '$' in line:
            line = line.split('$')[0].strip()
            if not line:
                continue

        # 3. 处理纯正则匹配规则: /^admaster\./ -> DOMAIN-REGEX
        if line.startswith('/') and line.endswith('/'):
            regex_pattern = line[1:-1]
            if regex_pattern:
                domain_regex.add(regex_pattern)
            continue

        # 4. 处理 ||example.org^ 基础子域阻断 -> DOMAIN-SUFFIX
        if line.startswith('||'):
            core = line[2:].rstrip('^/')
            
            # 丢弃带 * 或 ? 等复杂通配符的域名
            if '*' in core or '?' in core:
                continue

            # 验证提取的域名合规性
            if core and re.match(r'^[a-zA-Z0-9.\-_]+$', core):
                domain_suffix.add(core.lower())
            continue

        # 5. 处理 |http:// 或 |https:// 精确匹配 -> DOMAIN
        if line.startswith('|http://') or line.startswith('|https://'):
            core = line.split('://')[-1].split('/')[0].rstrip('^')
            if '*' not in core and re.match(r'^[a-zA-Z0-9.\-_]+$', core):
                domain_exact.add(core.lower())
            continue

        # 6. 处理纯域名形式 (如 example.org) -> DOMAIN-SUFFIX
        core = line.rstrip('^/')
        if '*' not in core and re.match(r'^[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,}$', core):
            domain_suffix.add(core.lower())

    # 去重优化：如果顶级域名已经在 domain_suffix 中，清除冗余的精确域名 (domain_exact)
    final_exact = {d for d in domain_exact if not any(d.endswith('.' + s) or d == s for s in domain_suffix)}

    return sorted(domain_suffix), sorted(final_exact), sorted(domain_regex)

def main():
    all_lines = []
    for url in SOURCES:
        print(f"正在抓取规则: {url}")
        all_lines.extend(fetch_rules(url))

    suffixes, exacts, regexes = parse_adguard_rules(all_lines)

    # 1. 输出转换清洗后的纯文本规则文件 (rules.txt)
    output_text_lines = []
    for s in suffixes:
        output_text_lines.append(f"DOMAIN-SUFFIX,{s}")
    for e in exacts:
        output_text_lines.append(f"DOMAIN,{e}")
    for r in regexes:
        output_text_lines.append(f"DOMAIN-REGEX,{r}")

    with open("rules.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output_text_lines))

    # 2. 导出供 Mihomo 编译使用的基础 YAML 文件
    output_yaml_lines = ["payload:"]
    for line in output_text_lines:
        output_yaml_lines.append(f"  - {line}")

    with open("rules_input.yaml", "w", encoding="utf-8") as f:
        f.write("\n".join(output_yaml_lines))

    print(f"解析成功: 已生成 rules.txt (包含 DOMAIN-SUFFIX {len(suffixes)} 条, DOMAIN {len(exacts)} 条, DOMAIN-REGEX {len(regexes)} 条)。")

if __name__ == "__main__":
    main()
