#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Email domain / MX / SMTP handshake checker

Что делает:
- принимает список email-адресов (из файла или из аргументов)
- проверяет существование домена (DNS)
- проверяет MX-записи домена
- делает SMTP "handshake" до RCPT TO (best-effort, письмо НЕ отправляет)
- выводит статус:
  - «домен валиден»
  - «домен отсутствует»
  - «MX-записи отсутствуют или некорректны»

Важно:
- многие почтовые провайдеры не дают честно проверить "существует ли пользователь"
  (анти-спам), поэтому SMTP результат может быть 4xx/5xx даже для реальных ящиков.
"""

from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

import dns.exception
import dns.resolver

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class DnsResult:
    domain_exists: bool
    has_mx: bool
    mx_hosts: List[Tuple[int, str]]  # (preference, host)


@dataclass
class SmtpResult:
    attempted: bool
    ok: bool
    code: Optional[int]
    message: str
    server: Optional[str]


def parse_emails_from_file(path: str) -> List[str]:
    emails: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # допускаем разделение пробелами/запятыми
            parts = re.split(r"[,\s]+", line)
            for p in parts:
                p = p.strip()
                if p:
                    emails.append(p)
    return emails


def validate_email_format(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


def extract_domain(email: str) -> str:
    return email.split("@", 1)[1].lower().strip(".")


def dns_check(domain: str, timeout: float = 3.0) -> DnsResult:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    # Проверка существования домена:
    # NXDOMAIN -> домена нет. NoAnswer/Timeout -> домен может быть, но запись не ответила.
    domain_exists = True
    try:
        try:
            resolver.resolve(domain, "A")
        except dns.resolver.NoAnswer:
            try:
                resolver.resolve(domain, "AAAA")
            except dns.resolver.NoAnswer:
                pass
    except dns.resolver.NXDOMAIN:
        domain_exists = False
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.YXDOMAIN):
        domain_exists = True

    mx_hosts: List[Tuple[int, str]] = []
    has_mx = False
    if domain_exists:
        try:
            answers = resolver.resolve(domain, "MX")
            for r in answers:
                mx_hosts.append((int(r.preference), str(r.exchange).rstrip(".")))
            mx_hosts.sort(key=lambda x: x[0])
            has_mx = len(mx_hosts) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            has_mx = False
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            has_mx = False

    return DnsResult(domain_exists=domain_exists, has_mx=has_mx, mx_hosts=mx_hosts)


def _parse_smtp_code(line: str) -> Optional[int]:
    if not line:
        return None
    m = re.match(r"^(\d{3})\b", line.strip())
    if not m:
        return None
    return int(m.group(1))


def _recv_line(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if len(data) > 8192:
            break
    return data.decode("utf-8", errors="replace").strip()


def _send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\r\n").encode("utf-8"))


def smtp_handshake_check(
    email: str,
    mx_hosts: List[Tuple[int, str]],
    helo_host: str = "example.com",
    mail_from: str = "check@example.com",
    timeout: float = 6.0,
    max_mx_to_try: int = 2,
    use_starttls_if_offered: bool = True,
) -> SmtpResult:
    """
    Best-effort SMTP:
    - connect :25
    - EHLO
    - STARTTLS (если поддерживается)
    - MAIL FROM
    - RCPT TO (целевой email)
    - QUIT
    """
    if not mx_hosts:
        return SmtpResult(False, False, None, "SMTP пропущен: нет MX-хостов", None)

    to_try = mx_hosts[:max_mx_to_try]
    last_msg = "SMTP не выполнен"
    last_code: Optional[int] = None

    for _, host in to_try:
        server = host
        try:
            sock = socket.create_connection((server, 25), timeout=timeout)
        except OSError as e:
            last_msg = f"SMTP connect fail to {server}: {e}"
            continue

        try:
            _ = _recv_line(sock, timeout)  # banner

            _send_line(sock, f"EHLO {helo_host}")
            ehlo_lines = []
            line = _recv_line(sock, timeout)
            ehlo_lines.append(line)
            while line.startswith("250-"):
                line = _recv_line(sock, timeout)
                ehlo_lines.append(line)

            ehlo_text = "\n".join(ehlo_lines)
            supports_starttls = "STARTTLS" in ehlo_text.upper()

            if use_starttls_if_offered and supports_starttls:
                _send_line(sock, "STARTTLS")
                resp = _recv_line(sock, timeout)
                code = _parse_smtp_code(resp)
                if code and 200 <= code < 400:
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=server)

                    _send_line(sock, f"EHLO {helo_host}")
                    line = _recv_line(sock, timeout)
                    while line.startswith("250-"):
                        line = _recv_line(sock, timeout)

            _send_line(sock, f"MAIL FROM:<{mail_from}>")
            resp = _recv_line(sock, timeout)
            code = _parse_smtp_code(resp)
            if not code or code >= 400:
                last_code = code
                last_msg = f"{server}: MAIL FROM rejected: {resp}"
                _send_line(sock, "QUIT")
                _ = _recv_line(sock, timeout)
                continue

            _send_line(sock, f"RCPT TO:<{email}>")
            resp = _recv_line(sock, timeout)
            code = _parse_smtp_code(resp)
            last_code = code
            last_msg = f"{server}: RCPT response: {resp}"

            _send_line(sock, "QUIT")
            _ = _recv_line(sock, timeout)

            if code and 200 <= code < 300:
                return SmtpResult(True, True, code, f"SMTP RCPT принят (возможен catch-all): {resp}", server)
            if code and 500 <= code < 600:
                return SmtpResult(True, False, code, f"SMTP RCPT отклонён (hard fail): {resp}", server)
            if code and 400 <= code < 500:
                return SmtpResult(True, False, code, f"SMTP временный отказ/greylist: {resp}", server)

            return SmtpResult(True, False, code, f"SMTP ответ нестандартный: {resp}", server)

        except Exception as e:
            last_msg = f"{server}: SMTP handshake error: {e}"
            try:
                _send_line(sock, "QUIT")
            except Exception:
                pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return SmtpResult(True, False, last_code, last_msg, None)


def status_label(dns_res: DnsResult) -> str:
    if not dns_res.domain_exists:
        return "домен отсутствует"
    if not dns_res.has_mx:
        return "MX-записи отсутствуют или некорректны"
    return "домен валиден"


def main() -> int:
    parser = argparse.ArgumentParser(description="Email domain/MX/SMTP handshake checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Файл с email (строка/пробел/запятая)")
    group.add_argument("--emails", nargs="+", help="Email списком прямо в командной строке")

    parser.add_argument("--timeout-dns", type=float, default=3.0)
    parser.add_argument("--timeout-smtp", type=float, default=6.0)
    parser.add_argument("--max-mx", type=int, default=2)
    parser.add_argument("--no-smtp", action="store_true", help="Только DNS/MX, без SMTP")
    args = parser.parse_args()

    emails = parse_emails_from_file(args.file) if args.file else list(args.emails)
    if not emails:
        print("Нет email-адресов для проверки", file=sys.stderr)
        return 2

    for email in emails:
        email = email.strip()
        if not validate_email_format(email):
            print(f"{email}\tINVALID_FORMAT")
            continue

        domain = extract_domain(email)
        dns_res = dns_check(domain, timeout=args.timeout_dns)
        label = status_label(dns_res)

        mx_preview = ",".join([h for _, h in dns_res.mx_hosts[:3]]) if dns_res.mx_hosts else "-"

        if (not args.no_smtp) and dns_res.domain_exists and dns_res.has_mx:
            smtp_res = smtp_handshake_check(
                email=email,
                mx_hosts=dns_res.mx_hosts,
                timeout=args.timeout_smtp,
                max_mx_to_try=args.max_mx,
            )
            smtp_info = f"SMTP: {smtp_res.message}"
        else:
            smtp_info = "SMTP: skipped"

        print(f"{email}\t{label}\tMX: {mx_preview}\t{smtp_info}")

        time.sleep(0.1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
