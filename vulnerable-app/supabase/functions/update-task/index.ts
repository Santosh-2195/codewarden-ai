
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: corsHeaders,
    });
  }

  if (request.method !== "POST") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405, headers: corsHeaders }
    );
  }

  try {
    const body = await request.json();

    const taskId = body.taskId;
    const changes = body.changes;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { data, error } = await supabase
      .from("tasks")
      .update(changes)
      .eq("id", taskId)
      .select()
      .single();

    if (error) {
      throw error;
    }

    return Response.json(
      {
        success: true,
        task: data,
      },
      { headers: corsHeaders }
    );
  } catch (error) {
    return Response.json(
      {
        error: "Unable to update task",
        details: String(error),
      },
      {
        status: 500,
        headers: corsHeaders,
      }
    );
  }
});
