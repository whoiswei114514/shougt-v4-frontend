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
  admin_access: boolean;
  key_authenticated: boolean;
  session_key_assurance: KeyAssurance | null;
  fido_authenticated: boolean;
  session_scope: 'full' | 'enrollment' | 'impersonation';
  totp_enabled: boolean;
  show_real_name: boolean;
  primary_role_id: number | null;
  key_exempt_until: string | null;
  admin_suspended_until: string | null;
  impersonator_id: number | null;
  session_key_id?: number | null;
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
