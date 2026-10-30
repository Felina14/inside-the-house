"""The agent's three tools, built per session so each run has its own trace."""

import concurrent.futures
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urlparse

import boto3
from strands import tool

s3 = boto3.client("s3")
bedrock = boto3.client("bedrock-runtime")

DOCS_BUCKET = os.environ["DOCS_BUCKET"]
FETCH_TIMEOUT_S = 3


class _TextExtractor(HTMLParser):
    """Strip HTML to text but keep comments and <meta> content, so placement tests work."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self._skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "meta":
            a = dict(attrs)
            if a.get("content") and a.get("name"):
                self.parts.append(f"[meta {a['name']}: {a['content']}]")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())

    def handle_comment(self, data):
        self.parts.append(f"<!--{data}-->")


def html_to_text(html):
    p = _TextExtractor()
    p.feed(html)
    return "\n".join(p.parts)


def resolve(host, timeout=FETCH_TIMEOUT_S):
    """getaddrinfo with a timeout. Returns (addresses, error)."""
    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        fut = ex.submit(socket.getaddrinfo, host, 443, proto=socket.IPPROTO_TCP)
        try:
            return sorted({ai[4][0] for ai in fut.result(timeout=timeout)}), None
        except concurrent.futures.TimeoutError:
            return [], "dns timeout"
        except OSError as e:  # gaierror, and in Lambda an NXDOMAIN can surface as plain OSError (errno 16)
            return [], f"dns error: {e}"


def make_tools(trace, guardrail=None):
    """trace: dict the handler returns. guardrail: (id, version) to screen document text, or None."""

    def record(name, args, result, **extra):
        trace["tool_calls"].append(
            {"name": name, "args": args, "result": str(result)[:500], "t": round(time.time(), 3), **extra}
        )

    @tool
    def read_document(key: str) -> str:
        """Read a document from the user's folder and return its text.

        Args:
            key: The document key, exactly as listed in the folder.
        """
        try:
            body = s3.get_object(Bucket=DOCS_BUCKET, Key=key)["Body"].read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - the model sees the error, as with any real tool
            record("read_document", {"key": key}, f"error: {e}")
            return f"Error reading {key}: {e}"
        text = html_to_text(body)
        extra = {}
        if guardrail:
            # Bedrock Guardrails never sees toolResult content in a Converse call (see VERIFY.md §3),
            # so screen the document ourselves with ApplyGuardrail before the model gets it.
            r = bedrock.apply_guardrail(
                guardrailIdentifier=guardrail[0],
                guardrailVersion=guardrail[1],
                source="INPUT",
                content=[{"text": {"text": text}}],
            )
            extra["guardrail_action"] = r["action"]
            if r["action"] == "GUARDRAIL_INTERVENED":
                text = r["outputs"][0]["text"] if r.get("outputs") else "This document was blocked."
        record("read_document", {"key": key}, text, **extra)
        return text

    @tool
    def fetch_url(url: str) -> str:
        """Fetch a web page over HTTPS and return its body, or the error.

        Args:
            url: The full URL to fetch.
        """
        host = urlparse(url).hostname or ""
        addrs, dns_err = resolve(host) if host else ([], "no host in url")
        if dns_err:
            result = dns_err
        else:
            try:
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_S, context=ctx) as resp:
                    result = resp.read(2000).decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                result = f"connection error: {e}"
        record("fetch_url", {"url": url}, result, host=host, resolved=addrs, dns_error=dns_err)
        return result

    @tool
    def save_report(bucket: str, key: str, content: str) -> str:
        """Save a report to an S3 bucket.

        Args:
            bucket: The S3 bucket name.
            key: The object key, for example reports/summary.md.
            content: The report text.
        """
        args = {"bucket": bucket, "key": key, "content": content}
        try:
            s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))
            result, ok = f"Saved s3://{bucket}/{key}", True
        except Exception as e:  # noqa: BLE001
            result, ok = f"error: {e}", False
        record("save_report", args, result, succeeded=ok)
        return result

    return [read_document, fetch_url, save_report]
