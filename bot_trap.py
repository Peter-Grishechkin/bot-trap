#!/usr/bin/env python3
"""bot_trap.py — ловушка для самозванцев под видом Googlebot и YandexBot.

Читает access-лог сервера, находит запросы, которые подписаны как Googlebot или
бот Яндекса, и проверяет каждый IP по правилам самих поисковиков:
  • Google: обратный DNS → домен googlebot.com / google.com / googleusercontent.com →
    прямой DNS по этому имени вернул тот же IP (плюс списки IP-диапазонов Google).
  • Яндекс: обратный DNS → домен yandex.ru / yandex.net / yandex.com → прямой DNS
    вернул тот же IP. Списков IP Яндекс не публикует, поэтому только DNS.
Кроме того, ловит заход на «приманку» — адрес, закрытый в robots.txt и нигде не
упомянутый. Честные боты туда не ходят.

Только стандартная библиотека Python 3.8+. Ничего не ставится, ничего не блокируется:
скрипт читает логи и печатает отчёт.

Команды:
  setup                 придумать адрес-приманку и показать строку для robots.txt
  scan ЛОГ [ЛОГ ...]    проверить лог(и), поддерживается .gz
  check IP              проверить один IP (--bot google|yandex)

Примеры — в README.md рядом со скриптом.
"""
import argparse
import collections
import csv
import gzip
import ipaddress
import json
import re
import secrets
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

# --- Какие User-agent считаем «подписью» бота ------------------------------------
# Список можно править. Для Яндекса взяты роботы из справки Яндекса; мобильное
# приложение YandexSearch/ и YaBrowser намеренно не входят: это живые люди.
GOOGLE_UA = re.compile(
    r"Googlebot|AdsBot-Google|Mediapartners-Google|Storebot-Google|Google-InspectionTool|"
    r"GoogleOther|APIs-Google|FeedFetcher-Google|Google-Read-Aloud|Google-Site-Verification",
    re.I,
)
YANDEX_UA = re.compile(
    r"Yandex(?:Bot|Mobile|Access|AdNet|Blogs|Calendar|Direct|Favicons|Feed|Image|Market|Media|"
    r"Metrika|OntoDB|Pagechecker|Partner|RCA|RenderResources|Screenshot|Sitelinks|Sprav|"
    r"Tracker|Userproxy|Vertis|Verticals|Video|Webmaster|Additional|ComBot|CheckBot|Dialogs|"
    r"SearchShop)|YaDirectFetcher|YaComBot",
    re.I,
)

SUFFIXES = {
    "google": (".googlebot.com", ".google.com", ".googleusercontent.com"),
    "yandex": (".yandex.ru", ".yandex.net", ".yandex.com"),
}
BOT_TITLE = {"google": "Google", "yandex": "Яндекс"}

GOOGLE_RANGE_URLS = [
    "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json",
]

# Формат combined (nginx и Apache по умолчанию). Для других форматов есть --regex.
COMBINED = (
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+ "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

CACHE_TTL = 24 * 3600


# --- Проверка IP -----------------------------------------------------------------
def _ip(value):
    try:
        return ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return None


def verify_dns(ip, bot):
    """Возвращает (вердикт, имя хоста, пояснение). Вердикт: verified / fake / unknown."""
    suffixes = SUFFIXES[bot]
    try:
        host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except socket.herror as e:
        if e.args and e.args[0] == 1:
            return "fake", "", "у IP нет PTR-записи"
        return "unknown", "", f"сбой DNS: {e}"
    except OSError as e:
        return "unknown", "", f"сбой DNS: {e}"

    if not host.endswith(suffixes):
        return "fake", host, f"PTR {host} не из доменов {BOT_TITLE[bot]}"

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        not_found = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}
        if e.args and e.args[0] in not_found:
            return "fake", host, "прямой DNS не знает такого имени"
        return "unknown", host, f"сбой DNS: {e}"
    except OSError as e:
        return "unknown", host, f"сбой DNS: {e}"

    forward = {_ip(i[4][0]) for i in infos}
    if _ip(ip) in forward:
        return "verified", host, "обратный и прямой DNS сошлись"
    return "fake", host, "прямой DNS вернул другой IP"


def load_google_ranges(cache_dir, use_net=True):
    """Списки IP Google: свежий кэш → скачивание → устаревший кэш → пусто."""
    cache = cache_dir / "google_ranges.json"
    fresh = cache.exists() and time.time() - cache.stat().st_mtime < CACHE_TTL
    raw = None
    if fresh:
        raw = json.loads(cache.read_text())
    elif use_net:
        prefixes = []
        try:
            for url in GOOGLE_RANGE_URLS:
                req = Request(url, headers={"User-Agent": "bot-trap/1.0"})
                with urlopen(req, timeout=15) as r:
                    prefixes += json.load(r).get("prefixes", [])
            raw = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in prefixes]
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(raw))
        except Exception as e:  # сеть недоступна — работаем только по DNS
            print(f"Внимание: списки IP Google не скачались ({e}); проверяю только по DNS.", file=sys.stderr)
    if raw is None and cache.exists():
        raw = json.loads(cache.read_text())
    nets = []
    for p in raw or []:
        try:
            nets.append(ipaddress.ip_network(p))
        except (ValueError, TypeError):
            pass
    return nets


class Verifier:
    def __init__(self, cache_dir, use_ranges=True, workers=16):
        self.cache_dir = cache_dir
        self.workers = workers
        self.ranges = load_google_ranges(cache_dir, use_ranges) if use_ranges else []
        self.cache_file = cache_dir / "dns_cache.json"
        self.cache = {}
        if self.cache_file.exists():
            try:
                self.cache = json.loads(self.cache_file.read_text())
            except ValueError:
                self.cache = {}

    def _one(self, key):
        bot, ip = key
        addr = _ip(ip)
        if addr is None:
            return "skip", "", "не IP-адрес"
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "skip", "", "локальный IP — в логе, похоже, адрес прокси или CDN"
        if bot == "google" and any(addr in n for n in self.ranges if n.version == addr.version):
            return "verified", "", "IP из списков Google"
        cached = self.cache.get(f"{bot}|{ip}")
        if cached and time.time() - cached["ts"] < CACHE_TTL:
            return cached["v"], cached["host"], cached["why"]
        res = verify_dns(ip, bot)
        if res[0] == "unknown":  # один повтор: DNS иногда сбоит
            time.sleep(1)
            res = verify_dns(ip, bot)
        if res[0] in ("verified", "fake"):
            self.cache[f"{bot}|{ip}"] = {"v": res[0], "host": res[1], "why": res[2], "ts": time.time()}
        return res

    def run(self, keys):
        keys = list(keys)
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = dict(zip(keys, pool.map(self._one, keys)))
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self.cache))
        except OSError:
            pass
        return results


# --- Чтение логов ----------------------------------------------------------------
def open_log(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def claimed_bot(ua):
    if GOOGLE_UA.search(ua):
        return "google"
    if YANDEX_UA.search(ua):
        return "yandex"
    return None


def first_ip(token):
    return token.split(",")[0].strip()


def parse_logs(paths, rx, traps):
    stats = collections.defaultdict(lambda: {
        "n": 0, "first": "", "last": "", "paths": collections.Counter(),
        "status": collections.Counter(), "ua": "",
    })
    trap_hits = collections.defaultdict(lambda: {"n": 0, "ua": "", "bot": None, "paths": collections.Counter()})
    total = skipped = 0
    for path in paths:
        with open_log(path) as f:
            for line in f:
                total += 1
                m = rx.match(line)
                if not m:
                    skipped += 1
                    continue
                d = m.groupdict()
                ip = first_ip(d["ip"])
                ua = d.get("ua") or ""
                url = (d.get("path") or "").split("?")[0]
                bot = claimed_bot(ua)
                if bot:
                    s = stats[(bot, ip)]
                    s["n"] += 1
                    s["first"] = s["first"] or (d.get("time") or "")
                    s["last"] = d.get("time") or s["last"]
                    s["paths"][url] += 1
                    s["status"][d.get("status") or "?"] += 1
                    s["ua"] = s["ua"] or ua
                if any(url.startswith(t) for t in traps):
                    t = trap_hits[ip]
                    t["n"] += 1
                    t["ua"] = t["ua"] or ua
                    t["bot"] = t["bot"] or bot
                    t["paths"][url] += 1
    return stats, trap_hits, total, skipped


# --- Команды ---------------------------------------------------------------------
def cmd_setup(args):
    path = f"/{args.prefix}-{secrets.token_hex(3)}/"
    print(f"Адрес-приманка: {path}\n")
    print("1. Добавьте в robots.txt (в существующую группу User-agent: *, комментарии не нужны):\n")
    print(f"   Disallow: {path}\n")
    print("2. Нигде больше этот адрес не упоминайте: ни в ссылках, ни в sitemap.xml.")
    print("   Страницу создавать не надо: запрос к несуществующему адресу тоже попадает в лог.\n")
    print("3. Через несколько дней запустите проверку:\n")
    print(f"   python3 bot_trap.py scan /путь/к/access.log --trap {path}")


def cmd_check(args):
    bots = [args.bot] if args.bot else ["google", "yandex"]
    v = Verifier(Path(args.cache_dir), use_ranges=not args.no_ranges)
    res = v.run([(b, args.ip) for b in bots])
    for b in bots:
        verdict, host, why = res[(b, args.ip)]
        print(f"{BOT_TITLE[b]:7} {verdict:9} {host or '-':45} {why}")


def short(ua, n=60):
    return ua if len(ua) <= n else ua[: n - 1] + "…"


def cmd_scan(args):
    rx = re.compile(args.regex or COMBINED)
    missing = {"ip", "path", "ua"} - set(rx.groupindex)
    if missing:
        sys.exit(f"В --regex нужны группы: ip, path, ua (нет: {', '.join(sorted(missing))})")
    traps = [t if t.startswith("/") else "/" + t for t in (args.trap or [])]

    stats, trap_hits, total, skipped = parse_logs(args.logs, rx, traps)
    print(f"Прочитано строк: {total}; не разобрано: {skipped}")
    if total and skipped / total > 0.5:
        print("ВНИМАНИЕ: больше половины строк не разобрано. Формат лога не combined? Задайте --regex.")

    keys = set(stats)
    keys |= {(t["bot"], ip) for ip, t in trap_hits.items() if t["bot"]}
    verifier = Verifier(Path(args.cache_dir), use_ranges=not args.no_ranges, workers=args.workers)
    print(f"Уникальных IP «ботов» к проверке: {len(keys)}\n")
    verdicts = verifier.run(keys)

    rows = []
    for (bot, ip), s in stats.items():
        verdict, host, why = verdicts[(bot, ip)]
        rows.append({"bot": bot, "ip": ip, "verdict": verdict, "host": host, "why": why, **s})

    # Сводка по каждому поисковику
    for bot in ("google", "yandex"):
        part = [r for r in rows if r["bot"] == bot]
        if not part:
            continue
        sums = collections.Counter()
        ips = collections.Counter()
        for r in part:
            sums[r["verdict"]] += r["n"]
            ips[r["verdict"]] += 1
        all_n = sum(sums.values())
        print(f"== {BOT_TITLE[bot]}: {all_n} запросов с подписью бота, {len(part)} IP")
        for key, title in (("verified", "настоящие"), ("fake", "САМОЗВАНЦЫ"),
                           ("unknown", "не удалось проверить (сбой DNS)"), ("skip", "локальные IP")):
            if ips[key]:
                print(f"   {title:35} {sums[key]:>8} запросов ({sums[key] / all_n:5.1%}), {ips[key]} IP")
        if len(part) >= 5 and ips["verified"] == 0 and ips["fake"] + ips["skip"] == len(part):
            print("   ВНИМАНИЕ: ни один IP не подтвердился. Скорее всего, в логе адреса прокси или CDN,"
                  " а не посетителей. Пока не настроите реальный IP в логе (X-Forwarded-For и т. п.),"
                  " этим вердиктам верить нельзя.")
        print()

    fakes = sorted((r for r in rows if r["verdict"] == "fake"), key=lambda r: -r["n"])
    if fakes:
        print("== Самозванцы (по числу запросов)")
        for r in fakes[: args.top]:
            top = ", ".join(f"{p} ×{c}" for p, c in r["paths"].most_common(3))
            codes = " ".join(f"{k}:{v}" for k, v in r["status"].most_common(3))
            print(f"   {r['ip']:40} {BOT_TITLE[r['bot']]:7} {r['n']:>6} зап.  коды {codes}")
            print(f"      причина: {r['why']}")
            print(f"      первый/последний: {r['first']} → {r['last']}")
            print(f"      чаще всего: {top}")
        if len(fakes) > args.top:
            print(f"   … и ещё {len(fakes) - args.top} IP (все в --csv)")
        print()

    # Приманка
    deny_extra = set()
    if traps:
        print(f"== Приманка {', '.join(traps)}: заходов {sum(t['n'] for t in trap_hits.values())}, IP {len(trap_hits)}")
        for ip, t in sorted(trap_hits.items(), key=lambda kv: -kv[1]["n"])[: args.top]:
            if t["bot"]:
                verdict, host, why = verdicts[(t["bot"], ip)]
            else:
                verdict, host, why = None, "", ""
            if verdict == "fake":
                note = f"подпись {BOT_TITLE[t['bot']]}, но проверка не пройдена: самозванец, ловушка сработала"
                deny_extra.add(ip)
            elif verdict == "verified":
                note = (f"настоящий бот {BOT_TITLE[t['bot']]} зашёл в закрытый раздел: проверьте, что Disallow стоит в нужной "
                        "группе robots.txt и файл отдаётся с кодом 200")
                if t["bot"] == "yandex":
                    note += "; часть роботов Яндекса (например, YandexDirect, YandexMetrika) robots.txt не учитывает"
            elif verdict in ("unknown", "skip"):
                note = f"подпись {BOT_TITLE[t['bot']]}, проверить не удалось ({why})"
            else:
                note = "не бот Google/Яндекса, но robots.txt проигнорировал: кандидат на блокировку, посмотрите вручную"
                a = _ip(ip)
                if a and not (a.is_private or a.is_loopback or a.is_link_local):
                    deny_extra.add(ip)
            print(f"   {ip:40} {t['n']:>4} зап.  {short(t['ua'])}")
            print(f"      {note}")
        print()
    if not fakes and not trap_hits:
        print("Самозванцев не найдено.")

    # Файлы
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["бот", "ip", "вердикт", "хост", "причина", "запросов", "первый", "последний", "частые адреса"])
            for r in sorted(rows, key=lambda r: (r["verdict"], -r["n"])):
                w.writerow([r["bot"], r["ip"], r["verdict"], r["host"], r["why"], r["n"], r["first"], r["last"],
                            "; ".join(f"{p} ×{c}" for p, c in r["paths"].most_common(5))])
        print(f"CSV: {args.csv}")

    if args.deny_file:
        deny = {r["ip"] for r in fakes}
        if args.deny_trap_hits:
            deny |= deny_extra
        fmt = {"nginx": "deny {};", "apache": "Require not ip {}", "plain": "{}"}[args.deny_format]
        with open(args.deny_file, "w", encoding="utf-8") as f:
            for ip in sorted(deny, key=lambda x: (_ip(x).version, _ip(x))):
                f.write(fmt.format(ip) + "\n")
        print(f"Список на блокировку ({len(deny)} IP): {args.deny_file} — сначала просмотрите, ничего не применено")

    if args.clean_out:
        fake_keys = {(r["bot"], r["ip"]) for r in fakes}
        kept = dropped = 0
        with open(args.clean_out, "w", encoding="utf-8") as out:
            for path in args.logs:
                with open_log(path) as f:
                    for line in f:
                        m = rx.match(line)
                        if m:
                            ua = m.group("ua") or ""
                            bot = claimed_bot(ua)
                            if bot and (bot, first_ip(m.group("ip"))) in fake_keys:
                                dropped += 1
                                continue
                        out.write(line)
                        kept += 1
        print(f"Лог без самозванцев: {args.clean_out} (оставлено {kept}, убрано {dropped})")


def main():
    p = argparse.ArgumentParser(description="Ловушка для самозванцев под видом Googlebot и YandexBot")
    p.add_argument("--cache-dir", default=str(Path.home() / ".cache" / "bot_trap"),
                   help="где хранить кэш DNS и списки IP Google")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="придумать адрес-приманку")
    s.add_argument("--prefix", default="seo-trap", help="начало адреса (по умолчанию seo-trap)")

    c = sub.add_parser("check", help="проверить один IP")
    c.add_argument("ip")
    c.add_argument("--bot", choices=["google", "yandex"])
    c.add_argument("--no-ranges", action="store_true", help="не скачивать списки IP Google")

    a = sub.add_parser("scan", help="проверить access-лог")
    a.add_argument("logs", nargs="+")
    a.add_argument("--trap", action="append", help="адрес-приманка (можно несколько раз)")
    a.add_argument("--regex", help="свой формат лога: нужны группы (?P<ip>) (?P<path>) (?P<ua>), по желанию time и status")
    a.add_argument("--csv", help="сохранить полный список IP в CSV")
    a.add_argument("--deny-file", help="сохранить список самозванцев для блокировки (ничего не применяется)")
    a.add_argument("--deny-format", choices=["nginx", "apache", "plain"], default="nginx")
    a.add_argument("--deny-trap-hits", action="store_true", help="добавить в список и тех, кто зашёл на приманку")
    a.add_argument("--clean-out", help="записать копию лога без запросов самозванцев (для анализа обхода)")
    a.add_argument("--no-ranges", action="store_true", help="не скачивать списки IP Google, только DNS")
    a.add_argument("--workers", type=int, default=16, help="потоков для DNS (по умолчанию 16)")
    a.add_argument("--top", type=int, default=20, help="сколько строк печатать в отчёте")

    args = p.parse_args()
    {"setup": cmd_setup, "check": cmd_check, "scan": cmd_scan}[args.cmd](args)


if __name__ == "__main__":
    main()
