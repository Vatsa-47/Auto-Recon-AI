"""
AUTO-RECON AI — Deployment Bundle Size Verification Script
Simulates and measures the exact bundle size for:
1. Backend Function Deployment Bundle (Google Cloud Functions / Firebase Functions)
2. Frontend Static Hosting Bundle
Validates that the function bundle is strictly below the 500 MB cloud deployment limit.
"""

import os
from pathlib import Path

def get_bundle_files(base_dir: Path, ignore_patterns: list):
    bundle_files = []
    base_dir = base_dir.resolve()
    for root, dirs, files in os.walk(base_dir):
        rel_root = Path(root).relative_to(base_dir)
        # Check dirs
        for f in files:
            rel_file = (rel_root / f).as_posix()
            
            # Check if ignored
            ignored = False
            for pat in ignore_patterns:
                pat_clean = pat.rstrip("/")
                if rel_file == pat_clean or rel_file.startswith(pat_clean + "/") or f == pat_clean:
                    ignored = True
                    break
                if pat.startswith("*.") and f.endswith(pat[1:]):
                    ignored = True
                    break
                if pat_clean in rel_file.split("/"):
                    ignored = True
                    break
            
            if not ignored:
                full_path = Path(root) / f
                try:
                    sz = full_path.stat().st_size
                    bundle_files.append((rel_file, sz))
                except OSError:
                    pass
    return bundle_files

def main():
    root = Path(".")
    
    # Backend Function Bundle rules (from firebase.json / .gcloudignore)
    backend_dir = root / "backend"
    backend_ignores = [
        "tests",
        "__pycache__",
        ".pytest_cache",
        "*.pyc",
        "storage/reports",
        "storage/datasets",
        "ml/data"
    ]
    
    backend_bundle = get_bundle_files(backend_dir, backend_ignores)
    backend_size = sum(sz for _, sz in backend_bundle)
    backend_mb = backend_size / (1024 * 1024)
    
    # Frontend Hosting Bundle rules
    frontend_files = ["index.html", "styles.css", "app.js", "sample-data.js", "auto_recon_synthetic_angle_crash.csv", "auto_recon_synthetic_angle_crash.json"]
    frontend_size = sum((root / f).stat().st_size for f in frontend_files if (root / f).exists())
    frontend_mb = frontend_size / (1024 * 1024)
    
    print("=" * 65)
    print("AUTO-RECON AI — DEPLOYMENT BUNDLE VERIFICATION AUDIT")
    print("=" * 65)
    print(f"Backend Function Bundle (FastAPI / PyTorch Core):")
    print(f"  - Total Files: {len(backend_bundle)}")
    print(f"  - Total Size:  {backend_mb:.2f} MB")
    print(f"  - Limit:       500.00 MB")
    print(f"  - Status:      {'PASS (Under 500 MB)' if backend_mb < 500 else 'FAIL (Exceeds 500 MB)'}")
    print("-" * 65)
    print(f"Frontend Static Hosting Bundle:")
    print(f"  - Total Files: {len(frontend_files)}")
    print(f"  - Total Size:  {frontend_mb:.2f} MB")
    print("-" * 65)
    print(f"Total Combined Production Footprint: {backend_mb + frontend_mb:.2f} MB")
    print("=" * 65)

    if backend_mb >= 500:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
