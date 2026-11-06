
#!/usr/bin/env python3

"""
CDF TaskFlow project structure validator.

Checks that expected source files exist and contain
basic structural markers.

Does not execute the application or perform
vulnerability detection.
"""

from pathlib import Path
import sys

APP_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "package.json",
    "index.html",
    "src/main.tsx",
    "src/App.tsx",
    "src/App.css",
    "src/index.css",
    "src/types.ts",
    "src/components/TaskComments.tsx",
    "src/lib/demoConfig.ts",
    "supabase/README.md",
    "supabase/functions/update-task/index.ts",
    "supabase/functions/get-profile/index.ts",
    "supabase/functions/search-tasks/index.ts",
    "supabase/migrations/001_initial_schema.sql",
    "supabase/migrations/002_access_policies.sql",
]

STRUCTURAL_CHECKS = {
    "src/App.tsx": [
        "CDF TaskFlow",
        "Task Dashboard",
        "My Profile",
        "TaskComments",
    ],
    "src/components/TaskComments.tsx": [
        "onAddComment",
        "comments.map",
    ],
    "src/types.ts": [
        "TaskStatus",
        "TaskComment",
        "Task",
        "User",
    ],
    "supabase/migrations/001_initial_schema.sql": [
        "CREATE TABLE public.profiles",
        "CREATE TABLE public.tasks",
        "ENABLE ROW LEVEL SECURITY",
    ],
    "supabase/migrations/002_access_policies.sql": [
        "CREATE POLICY",
        "ON public.tasks",
    ],
}


def main():
    print("=" * 55)
    print("CDF TaskFlow - Project Validation")
    print("=" * 55)

    errors = []

    print("\nChecking required files...\n")

    for relative_path in REQUIRED_FILES:
        file_path = APP_ROOT / relative_path

        if file_path.is_file():
            print(f"[PASS] {relative_path}")
        else:
            print(f"[FAIL] {relative_path}")
            errors.append(f"Missing file: {relative_path}")

    print("\nChecking source structure...\n")

    for relative_path, markers in STRUCTURAL_CHECKS.items():
        file_path = APP_ROOT / relative_path

        if not file_path.is_file():
            continue

        content = file_path.read_text(encoding="utf-8")

        for marker in markers:
            if marker in content:
                print(f"[PASS] {relative_path}: {marker}")
            else:
                print(f"[FAIL] {relative_path}: {marker}")
                errors.append(
                    f"Missing marker in {relative_path}: {marker}"
                )

    print("\n" + "=" * 55)

    if errors:
        print(f"Validation failed: {len(errors)} issue(s)")
        for error in errors:
            print(f" - {error}")
        return 1

    print("Validation passed.")
    print("All expected files and markers are present.")
    print("\nNote: This does not verify security or runtime behavior.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
