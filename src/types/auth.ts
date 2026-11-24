export interface Certification { role: string; label: string }

export interface KeyAssurance {
  level: string;
  label: string;
  high_assurance: boolean;
  certifications: string[];
}

export interface SecurityState {
  email_verified: boolean;
  real_name_verified: boolean;
  advanced_verified: boolean;
  is_management: boolean;
  is_privileged: boolean;
  is_admin_candidate: boolean;
  admin_onboarding_required: boolean;
  admin_setup_ready: boolean;
  admin_keys_satisfied?: boolean;
  has_high_assurance_key?: boolean;
  external_key_count?: number;
  admin_access: boolean;
  key_authenticated: boolean;
  session_key_assurance: KeyAssurance | null;
  fido_authenticated: boolean;
  fido_fresh_seconds?: number;
  session_scope: 'full' | 'enrollment' | 'impersonation';
  totp_enabled: boolean;
  show_real_name: boolean;
  primary_role_id: number | null;
  key_exempt_until: string | null;
  admin_suspended_until: string | null;
  impersonator_id: number | null;
  session_key_id?: number | null;
  certificate_status?: 'valid' | 'expired' | 'missing' | 'not_required';
  certificate_expires_at?: string | null;
  certificate_required?: boolean;
  needs_certificate_issuance?: boolean;
  pending_issuance_count?: number;
  signed_issuance_ready_count?: number;
  pending_sign_requests_count?: number;
  can_sign_issuance_requests?: boolean;
  certificate_is_temporary?: boolean;
  certificate_is_ca?: boolean;
  self_issuance_available?: boolean;
}

export interface Quota {
  image_max_size: number;
}

export interface Permission {
  base_admin: boolean;

  admin_user: boolean;
  edit_user: boolean;
  edit_quota: boolean;
  edit_permission: boolean;
  login: boolean;
  change_password: boolean;
  create_user: boolean;

  admin_role: boolean;
  admin_forum: boolean;
  admin_report: boolean;

  no_review: boolean;

  admin_alumni: boolean;
  admin_file: boolean;
  admin_image: boolean;
  global_reader: boolean;
  super_admin: boolean;
  admin_admin: boolean;
  superadmin_admin: boolean;
}

export interface UserBrief {
  id: number;
  username: string;
  real_name: string;
  student_id: string;

  disabled?: boolean; // 是否在用户选择器中禁用
}

export interface User extends UserBrief {
  identity: string;
  school: string;
  date_joined: string;
  is_active: boolean;
  banned_until?: string | null;
  permanently_banned?: boolean;
  email: string;
  email_verified_at: string | null;
  real_name_verified_at: string | null;
  advanced_verified_at: string | null;
  primary_role_id: number | null;
  badges: Certification[];
}

export interface RoleBrief {
  id: number;
  name: string;
  avatar: string | null;
  verify: string | null;
  badges?: Certification[];

  is_private?: boolean;
  is_primary?: boolean;
  is_active?: boolean;
  banned_until?: string | null;
  permanently_banned?: boolean;
  unread_notification_count?: number;
}
export interface Role extends RoleBrief {
  description: string | null;
  user_info: UserBrief | null;
  is_active: boolean;
}
export interface RoleFull extends Role {
  description: string | null;
  editable: boolean;
  is_private: boolean;
  is_shared: boolean;
  show_user_info: boolean;
  show_like: boolean;
  followed: boolean;
  follower_count: number;
  following_count: number;
  members: UserBrief[];
  admins?: UserBrief[];
  is_owner?: boolean;
  is_admin?: boolean;
  banned_until?: string | null;
  permanently_banned?: boolean;
  external_links: {
    github: string;
    wechat: string;
    qq: string;
    twitter: string;
    weibo: string;
    douyin: string;
    other: string;
  };

  user_info: UserBrief | null;

  followLoading?: boolean;
}

export interface Authorization {
  payload: {
    v: number;
    session_id: string;
    user_id: number;
    user_version: number;
    exp: number;
    source?: string;
  };
  signature: string;
}

export interface AuthResponse {
  authorization: Authorization;
  captcha_required: boolean;
  captcha_expire_time: number;
  user: User;
  quota: Quota;
  permission: Permission;
  roles: RoleBrief[];
  signed: boolean;
  security: SecurityState;
  assigned_roles: string[];
  watermark_id: string;
}
