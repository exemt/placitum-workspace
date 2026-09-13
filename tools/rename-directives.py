#!/usr/bin/env python3
"""Механическая часть переименования директив в конфигах nginx.

Слияния делаются по двум строкам подряд, поэтому sed тут не годится: политика
уходит вторым словом к своему времени или размеру.

ВНИМАНИЕ: инструмент одноразовый и относится к той волне переименований.
Слияние waf_on_timeout вторым словом waf_deadline с тех пор отменено: политика
переехала в waf_exception <фаза> timeout pass|deny, и вывод этого преобразования
модуль сегодня отвергает на nginx -t. Переименования waf_body_max/preview/archive
остаются верными. Перед повторным запуском сверяйтесь с
docs/directives/list/deadline.md.
"""

import io
import re
import sys

POLICY = {"truncate": "trim", "trim": "trim", "block": "block", "pass": "pass"}


def convert(text: str) -> str:
    text = re.sub(
        r"(?m)^([ \t]*)waf_deadline([ \t]+)([^;\s]+);\n[ \t]*waf_on_timeout[ \t]+(\w+);",
        lambda m: f"{m[1]}waf_deadline{m[2]}{m[3]} {m[4]};",
        text,
    )
    text = re.sub(
        r"(?m)^([ \t]*)waf_response_deadline([ \t]+)([^;\s]+);\n[ \t]*waf_on_response_timeout[ \t]+(\w+);",
        lambda m: f"{m[1]}waf_response_deadline{m[2]}{m[3]} {m[4]};",
        text,
    )
    text = re.sub(
        r"(?m)^([ \t]*)waf_body_max([ \t]+)([^;\s]+);\n([ \t]*)waf_on_body_oversize[ \t]+(\w+);",
        lambda m: f"{m[1]}waf_body_limit{m[2]}{m[3]} {POLICY[m[5]]};",
        text,
    )
    text = re.sub(r"(?m)^[ \t]*waf_body_inline_max[ \t]+[^;]+;[ \t]*\n", "", text)
    text = text.replace("waf_body_max", "waf_body_limit")
    text = text.replace("waf_request_archive ", "waf_archive request ")
    text = text.replace("waf_headers_preview ", "waf_preview headers ")
    text = text.replace("waf_args_preview ", "waf_preview args ")
    text = text.replace("waf_body_preview ", "waf_preview body ")
    text = re.sub(r"(?m)^([ \t]*waf_preview[^;\n]*?)[ \t]+force;", r"\1;", text)
    return text


for path in sys.argv[1:]:
    with io.open(path, encoding="utf-8") as fh:
        before = fh.read()

    after = convert(before)
    if after == before:
        print(f"skip {path}")
        continue

    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(after)
    print(f"done {path}")
