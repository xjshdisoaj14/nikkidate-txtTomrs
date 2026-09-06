import re
import urllib.request

SOURCES = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt"
]

# 符合 RFC 标准的严格域名校验正则
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$')

def fetch_rules(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"[!] 下载失败: {url}, 错误信息: {e}")
        return []

def clean_domain(domain):
    """清洗并验证域名合法性"""
    if not domain:
        return None
    domain = domain.lower().strip('.')
    if '*' in domain or '?' in domain or '/' in domain or ':' in domain:
        return None
    if DOMAIN_REGEX.match(domain):
        return domain
    return None

def parse_adguard_rules(lines):
    domain_exact = set()
    domain_suffix = set()
    domain_regex = set()

    for line in lines:
        line = line.strip()
        # 1. 过滤空行、注释及元素选择器
        if not line or line.startswith('!') or line.startswith('#') or '##' in line or '#@#' in line or '#?#' in line:
            continue

        # 2. 剥离修饰符
        if '$' in line:
            line = line.split('$')[0].strip()
            if not line:
                continue

        # 3. 纯正则表达 -> DOMAIN-REGEX
        if line.startswith('/') and line.endswith('/'):
            regex_pattern = line[1:-1]
            if regex_pattern:
                domain_regex.add(regex_pattern)
            continue

        # 4. ||example.org^ 前缀阻断 -> DOMAIN-SUFFIX
        if line.startswith('||'):
            core = line[2:].rstrip('^/')
            clean = clean_domain(core)
            if clean:
                domain_suffix.add(clean)
            continue

        # 5. |http:// 精确阻断 -> DOMAIN
        if line.startswith('|http://') or line.startswith('|https://'):
            core = line.split('://')[-1].split('/')[0].rstrip('^')
            clean = clean_domain(core)
            if clean:
                domain_exact.add(clean)
            continue

        # 6. 纯域名 -> DOMAIN-SUFFIX
        core = line.rstrip('^/')
        clean = clean_domain(core)
        if clean:
            domain_suffix.add(clean)

    # 清除冗余包含项
    final_exact = {d for d in domain_exact if not any(d.endswith('.' + s) or d == s for s in domain_suffix)}

    return sorted(domain_suffix), sorted(final_exact), sorted(domain_regex)

def main():
    all_lines = []
    for url in SOURCES:
        print(f"正在抓取源文件: {url}")
        all_lines.extend(fetch_rules(url))

    suffixes, exacts, regexes = parse_adguard_rules(all_lines)

    # 1. 输出标准纯文本规则集 rules.txt (以 +. 为后缀标识，纯域名为精准标识)
    txt_lines = []
    for s in suffixes:
        txt_lines.append(f"+.{s}")
    for e in exacts:
        txt_lines.append(e)

    with open("rules.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines))

    # 2. 构造标准的中间构建 YAML，专供 Mihomo CLI 编译成 .mrs
    yaml_lines = ["payload:"]
    for s in suffixes:
        yaml_lines.append(f"  - DOMAIN-SUFFIX,{s}")
    for e in exacts:
        yaml_lines.append(f"  - DOMAIN,{e}")
    for r in regexes:
        yaml_lines.append(f"  - DOMAIN-REGEX,{r}")

    with open("rules_input.yaml", "w", encoding="utf-8") as f:
        f.write("\n".join(yaml_lines))

    print(f"提取完成！后缀规则: {len(suffixes)} 条，精确规则: {len(exacts)} 条，正则规则: {len(regexes)} 条。")

if __name__ == "__main__":
    main()
