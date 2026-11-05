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
from gt_auth.models import ClientCertificateIdentity, Role, RoleMember
from gt_forum.models import Post, PostVersion
from backend.certificates import CertificateVerifier
from tests.certificates_fixture import PKI

call_command("migrate", verbosity=0, interactive=False)
normal, _ = make_user("ui_student")
alternate = Role.objects.create(name="浏览器测试备用角色")
RoleMember.objects.create(user=normal, role=alternate, is_owner=True)
root, _ = make_user("ui_root", roles=["super_admin"])
root.student_id = "shou-ui_root"
root.save(update_fields=["student_id"])
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
(work / "fixture.json").write_text(json.dumps(fixture), encoding="utf-8")
print("Created isolated browser fixtures and test-only certificate authority")
