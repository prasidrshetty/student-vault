
-- Create safe views without hash fields
CREATE OR REPLACE VIEW public.folders_safe AS
SELECT id, user_id, name, color, icon, is_default, created_at, updated_at
FROM public.folders;

CREATE OR REPLACE VIEW public.user_settings_safe AS
SELECT id, user_id, app_lock_enabled, biometric_enabled, created_at, updated_at
FROM public.user_settings;

-- Enable RLS on the views via security_invoker
ALTER VIEW public.folders_safe SET (security_invoker = on);
ALTER VIEW public.user_settings_safe SET (security_invoker = on);
