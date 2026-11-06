CREATE TABLE public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id),
    email TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE public.notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES auth.users(id),
    title TEXT NOT NULL,
    body TEXT
);

CREATE TABLE public.shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    note_id UUID NOT NULL REFERENCES public.notes(id),
    shared_with UUID NOT NULL REFERENCES auth.users(id)
);

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Read notes"
ON public.notes
FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Update own user"
ON public.users
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

-- Safe decoy: properly scoped write policy
CREATE POLICY "Owners update notes"
ON public.notes
FOR UPDATE
TO authenticated
USING (owner_id = auth.uid())
WITH CHECK (owner_id = auth.uid());

GRANT ALL ON public.notes TO anon;

CREATE OR REPLACE FUNCTION public.count_rows(tbl text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE n bigint;
BEGIN
  EXECUTE 'SELECT count(*) FROM ' || tbl INTO n;
  RETURN n;
END;
$$;
