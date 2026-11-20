# The newest released Fedora (Cloud Base)
image_url() {
  python3 -I - <<'PY'
import json, urllib.request
rel = json.load(urllib.request.urlopen("https://fedoraproject.org/releases.json", timeout=30))
imgs = [r for r in rel if r.get("arch") == "x86_64" and r.get("variant") == "Cloud"
        and r.get("link", "").endswith(".qcow2") and str(r.get("version", "")).isdigit()]
print(max(imgs, key=lambda r: int(r["version"]))["link"])
PY
}
