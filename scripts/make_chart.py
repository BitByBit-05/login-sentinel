"""Draw docs/images/timeline.png: one day of SSH logins from the sample log.

Steps:
  1. Parse sample_data/auth.log with the project's own parser.
  2. Count successful and failed logins in each 15-minute bucket.
  3. Draw them as stacked bars and label the three planted attacks.

Run:  pip install -e ".[charts]"   then   python scripts/make_chart.py
"""

from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt

from login_sentinel.parsers import parse_file

ROOT = Path(__file__).resolve().parent.parent
DAY = datetime(2026, 10, 12)
BUCKET = timedelta(minutes=15)

# Colours checked for colour-blind readers.
BLUE, ORANGE, GREY_TEXT, GRID = "#2a78d6", "#eb6834", "#52514e", "#e1e0d9"

ATTACKS = [
    (datetime(2026, 10, 12, 2, 8), "Password spray\n203.0.113.77"),
    (datetime(2026, 10, 12, 3, 17), "Brute force on root\n203.0.113.45"),
    (datetime(2026, 10, 12, 22, 43), "bob's password guessed\n192.0.2.99"),
]


def bucket_start(ts: datetime) -> datetime:
    """Round a time down to the start of its 15-minute bucket."""
    return DAY + (ts - DAY) // BUCKET * BUCKET


def main() -> None:
    events = parse_file(ROOT / "sample_data" / "auth.log", year=2026).events
    succeeded = Counter(bucket_start(e.timestamp) for e in events if e.success)
    failed = Counter(bucket_start(e.timestamp) for e in events if not e.success)

    buckets = [DAY + BUCKET * i for i in range(96)]  # 96 x 15 minutes = 24 hours
    x = [b + BUCKET / 2 for b in buckets]  # centre each bar in its bucket
    ok = [succeeded[b] for b in buckets]
    bad = [failed[b] for b in buckets]

    fig, ax = plt.subplots(figsize=(10, 4), dpi=150)
    width = BUCKET * 0.8
    ax.bar(x, ok, width=width, color=BLUE, label="Successful logins")
    ax.bar(x, bad, width=width, bottom=ok, color=ORANGE, label="Failed logins")

    for when, label in ATTACKS:
        height = succeeded[bucket_start(when)] + failed[bucket_start(when)]
        ax.annotate(label, xy=(when, height), xytext=(when, min(height + 8, 44)), ha="center",
                    fontsize=9, color=GREY_TEXT, arrowprops=dict(arrowstyle="-", color=GREY_TEXT))

    ax.set_xlim(DAY, DAY + timedelta(days=1))
    ax.set_ylim(0, 50)
    ax.xaxis.set_major_locator(mdates.HourLocator(byhour=range(0, 24, 3)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.set_ylabel("Logins per 15 minutes")
    ax.set_title("One day of SSH logins (sample auth.log, 12 Oct 2026)", loc="left", fontweight="bold")
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(frameon=False, loc="upper center", ncol=2)

    out = ROOT / "docs" / "images" / "timeline.png"
    fig.tight_layout()
    fig.savefig(out)
    print(f"Saved {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
