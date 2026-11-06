
import postgres from "npm:postgres@3.4.7";

Deno.serve(async (request: Request) => {
  if (request.method !== "GET") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405 }
    );
  }

  const url = new URL(request.url);
  const searchTerm = url.searchParams.get("q") ?? "";

  const sql = postgres(
    Deno.env.get("DATABASE_URL") ?? ""
  );

  try {
    const query = `
      SELECT id, title, description, status
      FROM public.tasks
      WHERE title ILIKE '%${searchTerm}%'
      ORDER BY created_at DESC
      LIMIT 25
    `;

    const tasks = await sql.unsafe(query);

    return Response.json({
      success: true,
      results: tasks,
    });
  } catch (error) {
    console.error("Task search failed:", error);

    return Response.json(
      { error: "Unable to search tasks" },
      { status: 500 }
    );
  } finally {
    await sql.end();
  }
});
