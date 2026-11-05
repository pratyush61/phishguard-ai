"""Command-line entry point (the dashboard is the main way to use PhishGuard).

  python main.py --mode demo      # run once on the sample emails
  python main.py --mode live      # one scan of the Gmail account saved in the dashboard (or .env)
"""
import argparse
import logging
import sys

import pipeline
import settings_store


def main():
    ap = argparse.ArgumentParser(description="PhishGuard AI - automated phishing detection")
    ap.add_argument("--mode", choices=["demo", "live"], default="demo")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if args.mode == "demo":
        r = pipeline.run_demo()
        print(f"\nDemo finished: {r.get('processed', 0)} sample emails processed. Start the dashboard with: python app.py")
        return
    if not settings_store.connected():
        sys.exit("No Gmail account connected. Run `python app.py` and use the Connect Gmail page.")
    print(pipeline.run_scan("gmail"))


if __name__ == "__main__":
    main()
