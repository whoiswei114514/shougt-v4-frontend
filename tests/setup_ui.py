import base64
import json
import os
import shutil
import sys
from pathlib import Path
from datetime import timedelta

front = Path(__file__).resolve().parents[1]
back = front.parent / "shougt-v0-backend"
console = front.parent / "shougt-sa"
work = Path(os.environ["SHOUGT_UI_WORK"]).resolve()
if any(work == root or work.is_relative_to(root / ".local-preview") for root in (front, back, console)):
    raise RuntimeError("Browser fixtures must use an isolated workspace, never a repository root or the persistent preview")
work.mkdir(parents=True, exist_ok=True)
(work / "mail").mkdir(exist_ok=True)
database = (work / "ui.sqlite3").resolve()
if not database.is_relative_to(work):
    raise RuntimeError("The test database must stay inside the requested test workspace")
if database.exists():
    database.unlink()
trust_file = (work / "fido-trust.json").resolve()
if not trust_file.is_relative_to(work):
    raise RuntimeError("Test trust metadata must stay inside the test workspace")
trust_file.unlink(missing_ok=True)
sys.path.insert(0, str(back))
sys.path.insert(0, str(console))
os.environ["DJANGO_SETTINGS_MODULE"] = "gt.ui_test_settings"
import django
django.setup()
from django.core.management import call_command
from django.conf import settings
from django.utils import timezone
from cryptography.hazmat.primitives import serialization
from gt_auth.test_support import make_user, add_key, PASSWORD
from gt_auth.models import ClientCertificateIdentity, Follow, Role, RoleMember
from gt_forum.models import Post, PostComment, PostVersion
from gt_admin.models import AdminAuditLog
from backend.certificates import CertificateVerifier
from tests.certificates_fixture import PKI

call_command("migrate", verbosity=0, interactive=False)
normal, _ = make_user("ui_student")
alternate = Role.objects.create(name="浏览器测试备用角色")
RoleMember.objects.create(user=normal, role=alternate, is_owner=True)
root, _ = make_user("ui_root", roles=["super_admin"])
root.student_id = "shou-ui_root"
root.save(update_fields=["student_id"])
trace_actor, _ = make_user("ui_trace_manager", roles=["admin_user"])
trace_actor.student_id = "shou-ui_trace_manager"
trace_actor.save(update_fields=["student_id"])
private_role = Role.objects.create(name="匿名关系测试角色", is_private=True)
RoleMember.objects.create(user=trace_actor, role=private_role, is_owner=True)
Follow.objects.create(follower=private_role, following=normal.primary_role)
private_post = Post.objects.create(author=trace_actor.primary_role, type=1, content="private fixture", share_with=-3)
orphan_post = Post.objects.create(author=None, type=1, content="orphaned private fixture", share_with=-3)
orphan_comment = PostComment.objects.create(post=private_post, author=None, user=trace_actor, content="orphaned private reply")
privacy_team = Role.objects.create(name="隐私回归共享角色", is_shared=True)
RoleMember.objects.create(user=trace_actor, role=privacy_team, is_owner=True)
RoleMember.objects.create(user=normal, role=privacy_team)
shared_post = Post.objects.create(author=privacy_team, type=1, content="shared privacy fixture", share_with=-3)
PostVersion.objects.create(post=shared_post, user=trace_actor, content=shared_post.content, images=[], share_with=-3)
shared_comment = PostComment.objects.create(post=shared_post, author=privacy_team, user=trace_actor, content="shared reply")
trace_marker = "4a13b07e2c8f9d1056a4e38b"
AdminAuditLog.objects.create(
    actor_id=trace_actor.pk, actor_name=trace_actor.username, roles=["admin_user"],
    action="GET /admin/user/", session_id="isolated-watermark-origin-session",
    watermark_id=trace_marker, details={"fixture_only": True},
)
pin_post = Post.objects.create(author=normal.primary_role, type=2, title="浏览器测试置顶文章", content="帖子置顶回归内容",
                               share_with=0, review_status=0, create_time=timezone.now() - timedelta(days=1))
PostVersion.objects.create(post=pin_post, user=normal, title=pin_post.title, content=pin_post.content,
                           images=[], share_with=0, review_status=0, version=1, create_time=pin_post.create_time)
audit_post = Post.objects.create(author=normal.primary_role, type=2, title="隔离环境 Markdown 审计样例",
    content='审计中的正常内容\n\n**正常加粗**\n\n<img src="/redteam-missing-image" onerror="window.__shouAuditExecuted=true">\n'
            '<a href="javascript:window.__shouAuditExecuted=true">危险链接</a>\n'
            '<iframe srcdoc="<script>parent.__shouAuditExecuted=true</script>"></iframe>',
    share_with=0, review_status=0)
key, virtual = add_key(root)
trust = [entry.copy() for entry in settings.FIDO_ATTESTATION_TRUST if entry.get("id") == "local-test-hardware"]
shutil.copyfile(trust[0]["root_pem"], work / "fido-root.pem")
trust[0]["root_pem"] = str(work / "fido-root.pem")
certified_key = os.environ.get("SHOUGT_UI_CERTIFIED_KEY") == "1"
if certified_key:
    trust[0].update(assurance="fips140-2-level2", certification_reference="ISOLATED UI TEST FIPS RECORD",
                    certifications=[{"standard": "CC", "level": "EAL4+", "reference": "ISOLATED UI TEST CC RECORD"}])
(work / "fido-trust.json").write_text(json.dumps(trust), encoding="utf-8")
pki = PKI(work / "pki", root.real_name)
cert = CertificateVerifier(pki.config).verify(pki.client_der)
ClientCertificateIdentity.objects.create(user=root, **cert)
config = {"origin":"https://privileged.localhost:18443", "main_origin":"http://localhost:15173",
          "host":"127.0.0.1", "port":18443, "database":{"engine":"sqlite","path":str(database)}, "tls":pki.config}
(work / "console.json").write_text(json.dumps(config), encoding="utf-8")
fixture = {"normal":{"username":normal.username,"password":PASSWORD,"user_id":normal.pk,
                     "alternate_role_id":alternate.pk,"alternate_role_name":alternate.name},
           "root":{"username":root.username,"password":PASSWORD,"user_id":root.pk,
                   "primary_role_id":root.primary_role_id,"real_name":root.real_name,"student_id":root.student_id,
                   "credential_id":base64.b64encode(virtual.id).decode(),
                   "private_key":base64.b64encode(virtual.private_key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode(),
                   "sign_count":key.sign_count},
           "certified_key":certified_key,
           "pin_post":{"id":pin_post.pk,"title":pin_post.title},
           "audit_post":{"id":audit_post.pk},
           "client_certificate":str(work / "pki/client.pem"),"client_key":str(work / "pki/client-key.pem")}
fixture["watermark_trace"] = {
    "marker": trace_marker, "actor_id": trace_actor.pk, "username": trace_actor.username,
    "sample": str(console / "tests/fixtures/watermarks/management.png"),
    "negative": str(console / "tests/fixtures/watermarks/negative.png"),
}
fixture["privacy_audit"] = {
    "orphan_post": orphan_post.pk, "orphan_comment": orphan_comment.pk,
    "private_post": private_post.pk, "private_role": private_role.pk,
    "shared_role": privacy_team.pk, "shared_post": shared_post.pk, "shared_comment": shared_comment.pk,
    "owner_username": trace_actor.username, "owner_real_name": trace_actor.real_name,
    "owner_student_id": trace_actor.student_id,
}
# Separate credentials keep new dual-key/read-only browser scenarios independent.
reader, _ = make_user("ui_reader", roles=["global_reader"])
reader_key, reader_virtual = add_key(reader)
dual, _ = make_user("ui_dual", roles=["super_admin"])
dual_key, dual_virtual = add_key(dual)
dual_second, dual_other = add_key(dual)
def browser_key(user, key, virtual):
    return {"username":user.username,"password":PASSWORD,"user_id":user.pk,"real_name":user.real_name,
            "credential_id":base64.b64encode(virtual.id).decode(),"sign_count":key.sign_count,
            "private_key":base64.b64encode(virtual.private_key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode()}
fixture["reader"] = browser_key(reader, reader_key, reader_virtual)
fixture["dual"] = browser_key(dual, dual_key, dual_virtual)
fixture["dual_second"] = browser_key(dual, dual_second, dual_other)
from tests.certificates_fixture import issue
reader_private, reader_cert = issue(reader.real_name, issuer=pki.sub, issuer_key=pki.sub_key, client=True)
pki.write_pair("reader", reader_cert, reader_private)
ClientCertificateIdentity.objects.create(user=reader, **CertificateVerifier(pki.config).verify(reader_cert.public_bytes(serialization.Encoding.DER)))
fixture["reader_certificate"] = str(work / "pki/reader.pem")
fixture["reader_private_key"] = str(work / "pki/reader-key.pem")
issuer, _ = make_user("ui_issuer", roles=["super_admin"])
issuer_key, issuer_virtual = add_key(issuer)
fixture["issuer"] = browser_key(issuer, issuer_key, issuer_virtual)
issuer_private, issuer_cert = issue(issuer.real_name, issuer=pki.sub, issuer_key=pki.sub_key, client=True)
pki.write_pair("issuer", issuer_cert, issuer_private)
ClientCertificateIdentity.objects.create(user=issuer, **CertificateVerifier(pki.config).verify(issuer_cert.public_bytes(serialization.Encoding.DER)))
fixture["issuer_certificate"] = str(work / "pki/issuer.pem")
fixture["issuer_private_key"] = str(work / "pki/issuer-key.pem")
recipient, _ = make_user("ui_issue_recipient", roles=["base_admin"])
add_key(recipient)
fixture["issuance_recipient"] = {"user_id":recipient.pk,"username":recipient.username}
onboarding, _ = make_user("ui_onboarding", roles=["admin_user"])
onboarding_key, onboarding_virtual = add_key(onboarding)
onboarding.admin_onboarding_required = True
onboarding.save(update_fields=["admin_onboarding_required"])
fixture["onboarding"] = browser_key(onboarding, onboarding_key, onboarding_virtual)
contact_user, _ = make_user("ui_contact_card")
contact_key, contact_virtual = add_key(contact_user)
fixture["contact_card"] = browser_key(contact_user, contact_key, contact_virtual)
phone_recipient, _ = make_user("ui_phone_recipient", roles=["base_admin"])
add_key(phone_recipient)
fixture["phone_recipient"] = {"user_id":phone_recipient.pk,"username":phone_recipient.username}
for label in ("webusb", "webusb_rsa"):
    web_recipient, _ = make_user("ui_" + label + "_recipient", roles=["base_admin"])
    add_key(web_recipient)
    fixture[label + "_recipient"] = {"user_id":web_recipient.pk,"username":web_recipient.username}
import secrets
fixture["piv_pair_code"] = secrets.token_urlsafe(18)
fixture["piv_phone_pair_code"] = secrets.token_urlsafe(18)
fixture["fido_pair_code"] = secrets.token_urlsafe(18)
(work / "pki/bridge-test-ca-key.pem").write_bytes(pki.sub_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
(work / "pki/bridge-test-rsa-ca-key.pem").write_bytes(pki.rsa_sub_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
(work / "webauthn-counter.json").write_text(str(key.sign_count), encoding="utf-8")
(work / "fixture.json").write_text(json.dumps(fixture), encoding="utf-8")
print("Created isolated browser fixtures and test-only certificate authority")
