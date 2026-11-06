
# CDF TaskFlow — Backend Source Files

This directory contains representative backend and
database source code for the CDF CyberSec Hackathon.

## Contents

### Edge Functions

- `functions/update-task/`: Updates task information.
- `functions/get-profile/`: Retrieves a user profile.
- `functions/search-tasks/`: Searches application tasks.

### Database

- `migrations/001_initial_schema.sql`: Database tables.
- `migrations/002_access_policies.sql`: Database access policies.

## Technology

The examples use:

- TypeScript
- Supabase-style Edge Functions
- PostgreSQL
- Supabase Row Level Security policies

## Running the Application

The frontend application uses local sample data.

These backend functions are included for source-code
review and do not need to be executed to use the
frontend demonstration.

No Supabase account or PostgreSQL installation is
required for the hackathon.

## Important

This repository is an intentionally vulnerable
educational application.

Do not deploy the backend functions or database
migrations, connect them to production services,
or use real credentials or customer data.

Participants should review the source code and
generate security findings and remediation guidance.
