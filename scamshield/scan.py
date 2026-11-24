"""`python -m scamshield.scan urls.csv --out predictions.csv` -> delegates to scamshield.cli (owner: verdict)."""
from scamshield.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
