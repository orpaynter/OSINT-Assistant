"""Local DecisionPackage verifier for Sovereign Intelligence Workstation."""

from __future__ import annotations

import argparse

from siw_core import DecisionPackageVerifier, model_dump_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify an SIW DecisionPackage locally")
    parser.add_argument("package", help="Path to .decisionpackage.json")
    args = parser.parse_args()
    result = DecisionPackageVerifier.verify(args.package)
    print(model_dump_json(result, indent=2))
    raise SystemExit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
