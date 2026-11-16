// Supabase Edge Function: create-officer
// Allows an active Super Admin to directly create an officer account (Auth user + profile + permissions)
// Deploy with: supabase functions deploy create-officer

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const ALLOWED_ROLES = new Set([
  'finance_secretary',
  'president',
  'general_secretary',
  'general_admin',
  'student_admin',
  'event_admin',
]);

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY') ?? '';
    const supabaseServiceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';

    if (!supabaseUrl || !supabaseAnonKey || !supabaseServiceRoleKey) {
      return new Response(JSON.stringify({ error: 'Server configuration missing' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const authHeader = req.headers.get('Authorization') ?? '';
    const callerClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const {
      data: { user: callerUser },
      error: authError,
    } = await callerClient.auth.getUser();

    if (authError || !callerUser) {
      return new Response(JSON.stringify({ error: 'অননুমোদিত অনুরোধ (Unauthorized)' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const adminClient = createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // Verify caller is an ACTIVE Super Admin
    const { data: callerProfile, error: profileErr } = await adminClient
      .from('profiles')
      .select('id, role, status')
      .eq('id', callerUser.id)
      .single();

    if (profileErr || !callerProfile || callerProfile.role !== 'super_admin' || callerProfile.status !== 'active') {
      return new Response(
        JSON.stringify({ error: 'শুধুমাত্র সক্রিয় সুপার অ্যাডমিন সরাসরি কর্মকর্তা তৈরি করতে পারেন।' }),
        {
          status: 403,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    const body = await req.json();
    const fullName = String(body?.fullName ?? '').trim();
    const email = String(body?.email ?? '').trim().toLowerCase();
    const phone = String(body?.phone ?? '').trim();
    const password = String(body?.password ?? '');
    const role = String(body?.role ?? 'general_admin');
const ALLOWED_PERMISSION_KEYS = [
  'can_view_finance',
  'can_entry_finance',
  'can_approve_finance',
  'can_view_reports',
  'can_export_reports',
  'can_correct_finance',
  'can_view_correction_history',
  'can_manage_funds',
  'can_manage_accounts',
  'can_manage_members',
  'can_manage_student_wing',
  'can_manage_committees',
  'can_manage_notices',
  'can_manage_settings',
  'can_export_backup',
  'can_event_view_module',
  'can_event_create',
  'can_event_edit',
  'can_event_manage_categories',
  'can_event_view_applications',
  'can_event_approve_application',
  'can_event_verify_payment',
  'can_event_manage_refund',
  'can_event_manage_ledger',
  'can_event_delete_test_data',
  'can_event_view_finance_summary',
  'can_event_export_reports',
  'can_event_manage_settings',
  'can_event_view_logs',
] as const;

    const rawPerms = body?.permissions && typeof body.permissions === 'object'
      ? (body.permissions as Record<string, unknown>)
      : {};
    const sanitizedPermissions: Record<string, boolean> = {};
    for (const key of ALLOWED_PERMISSION_KEYS) {
      if (key in rawPerms) {
        sanitizedPermissions[key] = Boolean(rawPerms[key]);
      }
    }

    if (!fullName || !email || password.length < 6) {
      return new Response(
        JSON.stringify({ error: 'নাম, বৈধ ইমেইল এবং কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন।' }),
        {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    if (!ALLOWED_ROLES.has(role)) {
      return new Response(JSON.stringify({ error: 'নির্বাচিত ভূমিকা (Role) বৈধ নয়।' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Create Auth User cleanly with email pre-confirmed
    const { data: created, error: createErr } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        full_name: fullName,
        phone,
        requested_role: role,
      },
    });

    if (createErr || !created.user) {
      return new Response(
        JSON.stringify({ error: createErr?.message || 'নতুন কর্মকর্তা অ্যাকাউন্ট তৈরি ব্যর্থ হয়েছে।' }),
        {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        }
      );
    }

    const newUserId = created.user.id;

    // Activate profile immediately since Super Admin created it
    const { error: profUpsertErr } = await adminClient.from('profiles').upsert(
      {
        id: newUserId,
        email,
        full_name: fullName,
        phone: phone || null,
        role,
        status: 'active',
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'id' }
    );

    if (profUpsertErr) {
      return new Response(JSON.stringify({ error: profUpsertErr.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Apply sanitized role permission matrix
    const { error: permUpsertErr } = await adminClient.from('admin_permissions').upsert(
      {
        user_id: newUserId,
        ...sanitizedPermissions,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'user_id' }
    );

    if (permUpsertErr) {
      return new Response(JSON.stringify({ error: permUpsertErr.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    return new Response(
      JSON.stringify({
        success: true,
        user: {
          id: newUserId,
          email,
          fullName,
          phone: phone || undefined,
          role,
          status: 'active',
          createdAt: created.user.created_at,
        },
      }),
      {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err instanceof Error ? err.message : 'Internal Edge Function Error' }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }
});
