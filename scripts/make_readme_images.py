"""Regenerate every image in docs/images/ from the real tool and test output.

Nothing is drawn by hand: the charts come from parsing sample_data/, the
terminal screenshots come from actually running the tool and the tests. If
the code changes, re-run this and the README stays truthful.

    pip install -e ".[dev,charts]"
    python scripts/make_readme_images.py

Charts are written in a light and a dark version; the README picks the one
that matches the reader's GitHub theme.
"""

import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # draw to files, no window
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
sys.path.insert(0, str(ROOT))

from login_sentinel.parsers import parse_file  # noqa: E402

# Colours validated for colour-blind separation and contrast on each surface.
THEMES = {
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9",
                  axis="#c3c2b7", band="#f0efec", success="#2a78d6", failed="#eb6834",
                  alert="#d03b3b", ok="#006300"),
    "dark": dict(surface="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a",
                 axis="#383835", band="#262624", success="#3987e5", failed="#d95926",
                 alert="#e66767", ok="#0ca30c"),
}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})


def style_axes(ax, t):
    ax.set_facecolor(t["surface"])
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(t["axis"])
    ax.tick_params(colors=t["muted"], length=0, labelsize=9)
    ax.grid(axis="y", color=t["grid"], linewidth=0.8)
    ax.set_axisbelow(True)


def load_linux_events():
    return parse_file(ROOT / "sample_data" / "auth.log", year=2026).events


# --- 1. Timeline of a day of logins -----------------------------------------

def timeline(theme: str) -> None:
    t = THEMES[theme]
    events = load_linux_events()
    day = datetime(2026, 10, 12)
    bin_minutes = 15

    def bucket(ts):
        return day + timedelta(minutes=(ts - day).total_seconds() // 60 // bin_minutes * bin_minutes)

    ok = Counter(bucket(e.timestamp) for e in events if e.success)
    bad = Counter(bucket(e.timestamp) for e in events if not e.success)
    bins = [day + timedelta(minutes=bin_minutes * i) for i in range(24 * 60 // bin_minutes)]
    width = timedelta(minutes=bin_minutes - 3)  # gap between bars
    centre = timedelta(minutes=bin_minutes / 2)

    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=160)
    fig.patch.set_facecolor(t["surface"])
    style_axes(ax, t)

    # Attack periods: neutral shaded bands with a text label.
    attacks = [
        (datetime(2026, 10, 12, 2, 5), datetime(2026, 10, 12, 2, 13), "Password spray\n203.0.113.77"),
        (datetime(2026, 10, 12, 3, 14), datetime(2026, 10, 12, 3, 20), "Brute force on root\n203.0.113.45"),
        (datetime(2026, 10, 12, 22, 41), datetime(2026, 10, 12, 22, 45), "bob's password guessed\n192.0.2.99"),
    ]
    for start, end, _ in attacks:
        ax.axvspan(start - timedelta(minutes=10), end + timedelta(minutes=10), color=t["band"], zorder=0)

    xs = [b + centre for b in bins]
    ok_h = [ok.get(b, 0) for b in bins]
    bad_h = [bad.get(b, 0) for b in bins]
    ax.bar(xs, ok_h, width=width, color=t["success"], label="Successful logins", edgecolor=t["surface"], linewidth=1)
    ax.bar(xs, bad_h, width=width, bottom=ok_h, color=t["failed"], label="Failed logins", edgecolor=t["surface"], linewidth=1)

    for (start, end, label), dx in zip(attacks, (-45, 70, -60), strict=True):
        peak = max(ok.get(b, 0) + bad.get(b, 0) for b in bins if start - timedelta(minutes=15) <= b <= end)
        ax.annotate(label, xy=(start + (end - start) / 2, peak + 0.6),
                    xytext=(start + timedelta(minutes=dx), peak + 7 if peak < 30 else 40),
                    ha="center", va="bottom", fontsize=9, color=t["ink2"],
                    arrowprops=dict(arrowstyle="-", color=t["muted"], linewidth=0.8))

    ax.set_xlim(day, day + timedelta(days=1))
    ax.set_ylim(0, 50)
    ax.xaxis.set_major_locator(mdates.HourLocator(byhour=range(0, 24, 3)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.set_ylabel("Logins per 15 minutes", color=t["ink2"], fontsize=9)
    ax.set_title("One day of SSH logins on web01 (sample auth.log, 12 Oct 2026)", loc="left",
                 color=t["ink"], fontsize=12, fontweight="bold", pad=24)
    legend = ax.legend(loc="upper left", bbox_to_anchor=(0, 1.1), ncol=2, frameon=False, fontsize=9,
                       handlelength=1, handleheight=1)
    for text in legend.get_texts():
        text.set_color(t["ink2"])
    fig.tight_layout()
    fig.savefig(OUT / f"timeline_{theme}.png", facecolor=t["surface"])
    plt.close(fig)


# --- 2. How the sliding window decides --------------------------------------

def sliding_window(theme: str) -> None:
    t = THEMES[theme]
    events = load_linux_events()

    def pick(ip, user=None):
        return [e for e in events if e.source_ip == ip and (user is None or e.user == user)]

    panels = [
        dict(events=pick("192.0.2.99", "bob"), window_end=datetime(2026, 10, 12, 22, 44, 40),
             xlim=(datetime(2026, 10, 12, 22, 33), datetime(2026, 10, 12, 22, 48)), tick_minutes=5,
             title="192.0.2.99 trying account 'bob'",
             verdict="ALERT: 6 failures in one window \u2192 brute_force, then a success \u2192 "
                     "success_after_failures (CRITICAL)", alert=True, rows=False),
        dict(events=pick("203.0.113.77"), window_end=datetime(2026, 10, 12, 2, 12, 20),
             xlim=(datetime(2026, 10, 12, 1, 59), datetime(2026, 10, 12, 2, 16)), tick_minutes=5,
             title="203.0.113.77 trying 12 different accounts",
             verdict="ALERT: 12 different accounts in one window \u2192 password_spray "
                     "(1 try each, so brute_force stays quiet)", alert=True, rows=True),
        dict(events=pick("203.0.113.200"), window_end=datetime(2026, 10, 12, 12, 11),
             xlim=(datetime(2026, 10, 12, 10, 30), datetime(2026, 10, 12, 13, 30)), tick_minutes=30,
             title="203.0.113.200 trying account 'root'",
             verdict="IGNORED: 3 tries over 2 hours, never more than 1 inside any 10-minute window",
             alert=False, rows=False),
    ]

    fig, axes = plt.subplots(3, 1, figsize=(10, 7.6), dpi=160, gridspec_kw=dict(height_ratios=[1, 2.6, 1]))
    fig.patch.set_facecolor(t["surface"])
    for ax, p in zip(axes, panels, strict=True):
        style_axes(ax, t)
        ax.grid(False)
        evs = p["events"]
        if p["rows"]:
            users = sorted({e.user for e in evs})
            ys = [users.index(e.user) for e in evs]
            ax.set_yticks(range(len(users)), users, fontsize=7.5)
            top = len(users) - 0.4
            ax.set_ylim(-0.8, len(users) + 0.6)
        else:
            ys = [0] * len(evs)
            ax.set_yticks([])
            top = 0.6
            ax.set_ylim(-0.8, 1.4)
        bottom = ax.get_ylim()[0] + 0.2

        # The 10-minute window that triggered (or failed to trigger) the rule.
        start = p["window_end"] - timedelta(minutes=10)
        x0, x1 = mdates.date2num(start), mdates.date2num(p["window_end"])
        ax.add_patch(Rectangle((x0, bottom), x1 - x0, top - bottom, fill=False, edgecolor=t["ink2"],
                               linewidth=1.2, linestyle=(0, (4, 3)), zorder=2))
        ax.text(start, top + 0.12, "10-minute window", va="bottom", fontsize=8, color=t["ink2"])

        colors = [t["success"] if e.success else t["failed"] for e in evs]
        ax.scatter([e.timestamp for e in evs], ys, s=48, c=colors, edgecolors=t["surface"], linewidths=1.5, zorder=3)

        ax.set_xlim(*p["xlim"])
        ax.xaxis.set_major_locator(mdates.MinuteLocator(byminute=range(0, 60, p["tick_minutes"])))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        ax.set_title(p["title"], loc="left", color=t["ink"], fontsize=10.5, fontweight="bold", pad=22)
        ax.text(0, 1.04, p["verdict"], transform=ax.transAxes, va="bottom", fontsize=9,
                color=t["alert"] if p["alert"] else t["ok"])

    handles = [plt.Line2D([], [], marker="o", linestyle="", markersize=7, color=t[k]) for k in ("failed", "success")]
    legend = fig.legend(handles, ["Failed login", "Successful login"], loc="upper left", bbox_to_anchor=(0.01, 0.955),
                        ncol=2, frameon=False, fontsize=9, handletextpad=0.3)
    for text in legend.get_texts():
        text.set_color(t["ink2"])
    fig.suptitle("How the sliding window decides (real events from the sample log)", x=0.012, y=0.99, ha="left",
                 color=t["ink"], fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.93), h_pad=1.6)
    fig.savefig(OUT / f"sliding_window_{theme}.png", facecolor=t["surface"])
    plt.close(fig)


# --- 3. Terminal screenshots ---------------------------------------------------

TERM = dict(bg="#1e1e1e", bar="#2d2d2d", text="#d4d4d4", dim="#8a8a8a", red="#f14c4c",
            orange="#f5a35c", green="#4ec97b", blue="#6cb6ff")


def line_colour(line: str) -> str:
    if line.startswith("$"):
        return TERM["blue"]
    if "CRITICAL" in line or "FAILED" in line:
        return TERM["red"]
    if "| HIGH" in line or line.startswith("[") and "HIGH" in line:
        return TERM["orange"]
    if " passed" in line or "100%" in line or "Required test coverage" in line:
        return TERM["green"]
    if line.startswith(("=", "-", "_")):
        return TERM["dim"]
    return TERM["text"]


def terminal(lines: list[str], name: str, title: str) -> None:
    width_chars = max(len(line) for line in lines)
    fig_w = max(7.5, width_chars * 0.072 + 0.6)
    fig_h = len(lines) * 0.19 + 0.75
    fig = plt.figure(figsize=(fig_w, fig_h), dpi=160)
    fig.patch.set_alpha(0)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, fig_w)
    ax.set_ylim(0, fig_h)
    ax.axis("off")
    ax.add_patch(FancyBboxPatch((0.02, 0.02), fig_w - 0.04, fig_h - 0.04, boxstyle="round,pad=0,rounding_size=0.12",
                                facecolor=TERM["bg"], edgecolor="#3c3c3c", linewidth=1))
    ax.add_patch(Rectangle((0.03, fig_h - 0.38), fig_w - 0.06, 0.34, facecolor=TERM["bar"], linewidth=0))
    for i, colour in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        ax.add_patch(plt.Circle((0.25 + i * 0.2, fig_h - 0.21), 0.055, color=colour))
    ax.text(fig_w / 2, fig_h - 0.21, title, ha="center", va="center", color=TERM["dim"], fontsize=8)
    for i, line in enumerate(lines):
        ax.text(0.25, fig_h - 0.62 - i * 0.19, line, family="DejaVu Sans Mono", fontsize=7.6,
                color=line_colour(line), va="center")
    fig.savefig(OUT / name, transparent=True)
    plt.close(fig)


def run(cmd: list[str]) -> list[str]:
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    return (result.stdout + result.stderr).rstrip("\n").splitlines()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        timeline(theme)
        sliding_window(theme)

    report_cmd = ["login-sentinel", "sample_data/auth.log", "sample_data/windows_security.csv", "--year", "2026"]
    report = run([sys.executable, "-m", "login_sentinel", *report_cmd[1:]])
    terminal(["$ " + " ".join(report_cmd), ""] + report, "terminal_report.png", "login-sentinel")

    tests = run([sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider", "--cov", "--cov-fail-under=95"])
    keep = [line for line in tests if "::" in line or "%" in line or "passed" in line or line.startswith(("Name", "---", "TOTAL", "Required"))]
    keep = [line.replace(str(ROOT) + "/", "") for line in keep]
    keep = [line.split(" PASSED")[0] + "  PASSED" if " PASSED" in line else line for line in keep]
    terminal(["$ pytest -v --cov", ""] + keep, "terminal_tests.png", "pytest")
    print(f"Images written to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
