
-- CDF TaskFlow
-- Sample database schema for source-code analysis.
--
-- This file is part of the hackathon demonstration
-- codebase. It is not required to run the frontend.
-- Do not deploy this sample application to production.

CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id)
        ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    bio TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('admin', 'member'))
);

CREATE TABLE public.projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL REFERENCES auth.users(id)
);

CREATE TABLE public.tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL
        REFERENCES public.projects(id)
        ON DELETE CASCADE,
    owner_id UUID NOT NULL
        REFERENCES auth.users(id),
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'To Do'
        CHECK (status IN ('To Do', 'In Progress', 'Done')),
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE public.task_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL
        REFERENCES public.tasks(id)
        ON DELETE CASCADE,
    author_id UUID NOT NULL
        REFERENCES auth.users(id),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Enable Row Level Security for application tables.
-- No client access policies are defined yet.
-- We will add representative policies in Stage 3.

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.task_comments ENABLE ROW LEVEL SECURITY;
