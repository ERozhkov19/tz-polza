#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Send text from .txt file to a private Telegram chat via Bot API.

Usage:
  export TG_BOT_TOKEN="..."
  export TG_CHAT_ID="..."

  python telegram_send.py --file message.txt
"""

from __future__ import annotations

import argparse
import os
import sys

import requests


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def send_message(token: str, chat_id: str, text: str, timeout: float = 15.0) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    r = requests.post(url, json=payload, timeout=timeout)
    if not r.ok:
        raise RuntimeError(f"Telegram API error: {r.status_code} {r.text}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a text file to Telegram chat via bot")
    parser.add_argument("--file", required=True, help="Path to .txt file")
    parser.add_argument("--token", default=os.getenv("TG_BOT_TOKEN"), help="Telegram bot token (or env TG_BOT_TOKEN)")
    parser.add_argument("--chat-id", default=os.getenv("TG_CHAT_ID"), help="Target chat id (or env TG_CHAT_ID)")
    args = parser.parse_args()

    if not args.token:
        print("Нет токена бота. Укажи --token или переменную окружения TG_BOT_TOKEN", file=sys.stderr)
        return 2
    if not args.chat_id:
        print("Нет chat_id. Укажи --chat-id или переменную окружения TG_CHAT_ID", file=sys.stderr)
        return 2

    text = read_text(args.file)
    if not text:
        print("Файл пустой — нечего отправлять", file=sys.stderr)
        return 2

    send_message(args.token, args.chat_id, text)
    print("OK: отправлено")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
