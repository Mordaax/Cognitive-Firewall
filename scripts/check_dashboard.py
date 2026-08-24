"""Rendered dashboard smoke check against an already running local stack."""

from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> None:
    screenshot = Path("docs/screenshots/dashboard.png")
    screenshot.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://127.0.0.1:8501", wait_until="networkidle", timeout=30_000)
        page.get_by_role("heading", name="Cognitive Firewall").wait_for(timeout=30_000)
        page.get_by_text("Total", exact=True).wait_for(timeout=10_000)
        assert "alice@example.com" not in page.content()
        page.screenshot(path=str(screenshot), full_page=True)
        browser.close()
    print("dashboard_render_ok", screenshot)


if __name__ == "__main__":
    main()
