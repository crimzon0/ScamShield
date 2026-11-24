"""python -m scamshield.evidence <scan_id> [--scan URL]"""
import asyncio
import json
import sys

from . import build_case


async def _main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m scamshield.evidence <scan_id> | --scan <url>", file=sys.stderr)
        return 2
    if argv[0] == "--bundle":
        from . import build_bundle

        path = await build_bundle(argv[1:])
        print(path)
        return 0 if path else 1
    if argv[0] == "--scan" and len(argv) > 1:
        from scamshield.pipeline import scan_url

        res = await scan_url(argv[1])
        print(f"scanned {argv[1]} -> scan_id={res.scan_id} {res.verdict.label} {res.verdict.score}")
        scan_id = res.scan_id
    else:
        scan_id = argv[0]
    case = await build_case(scan_id)
    print(json.dumps({"zip_path": case.zip_path, "pdf_path": case.pdf_path,
                      "manifest": case.manifest}, ensure_ascii=False, indent=2))
    return 0 if case.zip_path else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(asyncio.run(_main(sys.argv[1:])))
