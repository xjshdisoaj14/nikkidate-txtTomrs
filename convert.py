import re
import urllib.request

SOURCES = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt"
]

DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$')

def fetch_rules(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"[!] 下载失败: {url}, 错误: {e}")
        return []

def clean_domain(domain):
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

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#') or '##' in line or '#@#' in line or '#?#' in line:
            continue

        if '$' in line:
            line = line.split('$')[0].strip()
            if not line:
                continue

        # 过滤掉纯正则（纯文本 domain 规则集仅接收标准域名与后缀）
        if line.startswith('/') and line.endswith('/'):
            continue

        if line.startswith('||'):
            core = line[2:].rstrip('^/')
            clean = clean_domain(core)
            if clean:
                domain_suffix.add(clean)
            continue

        if line.startswith('|http://') or line.startswith('|https://'):
            core = line.split('://')[-1].split('/')[0].rstrip('^')
            clean = clean_domain(core)
            if clean:
                domain_exact.add(clean)
            continue

        core = line.rstrip('^/')
        clean = clean_domain(core)
        if clean:
            domain_suffix.add(clean)

    # 去重处理：若父级域名存在于后缀集合中，移除冗余的精确匹配项
    final_exact = {d for d in domain_exact if not any(d.endswith('.' + s) or d == s for s in domain_suffix)}

    return sorted(domain_suffix), sorted(final_exact)

def main():
    all_lines = []
    for url in SOURCES:
        print(f"正在读取规则源: {url}")
        all_lines.extend(fetch_rules(url))

    suffixes, exacts = parse_adguard_rules(all_lines)

    # 生成唯一的基准文件 rules.txt
    # +.example.com 代表后缀匹配，example.com 代表精确匹配
    txt_lines = []
    for s in suffixes:
        txt_lines.append(f"+.{s}")
    for e in exacts:
        txt_lines.append(e)

    with open("rules.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines))

    print(f"唯一基准文件 rules.txt 生成成功！包含后缀规则 {len(suffixes)} 条，精确规则 {len(exacts)} 条。")

if __name__ == "__main__":
    main()
