import argparse

from detector.service import analyze


def run_analysis(url: str) -> None:

    print("\nAnalyzing URL...\n")

    result = analyze(url)

    indicators = result.indicators

    if indicators:

        print("[!] Potential phishing indicators found:\n")

        for indicator in indicators:
            print(f" - {indicator.message}")

    else:
        print("No obvious phishing indicators found.")

    print(f"\nAnalysis complete, total indicators found: {len(indicators)}")
    print(f"\nRisk level: {result.risk_score}/10 ({result.risk_level.value})")


def main() -> None:

    parser = argparse.ArgumentParser(description="Phishing URL Analyzer")

    parser.add_argument(
        "url",
        help="URL to analyze"
    )

    args = parser.parse_args()

    run_analysis(args.url)


if __name__ == "__main__":
    main()