
-- CDF TaskFlow
-- Application database access policies.
-- Assumes tables from 001_initial_schema.sql exist.
--
-- Source-code review sample.
-- Not intended for deployment.

CREATE POLICY "Users can view profiles"
ON public.profiles
FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

CREATE POLICY "Users can view projects"
ON public.projects
FOR SELECT
TO authenticated
USING (owner_id = auth.uid());

CREATE POLICY "Users can create projects"
ON public.projects
FOR INSERT
TO authenticated
WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Users can create tasks"
ON public.tasks
FOR INSERT
TO authenticated
WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Users can update tasks"
ON public.tasks
FOR UPDATE
TO authenticated
USING (owner_id = auth.uid())
WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Users can view task comments"
ON public.task_comments
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM public.tasks
    WHERE tasks.id = task_comments.task_id
  )
);

CREATE POLICY "Users can add task comments"
ON public.task_comments
FOR INSERT
TO authenticated
WITH CHECK (author_id = auth.uid());
