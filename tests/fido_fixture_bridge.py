"""Browser fixture using python-fido2 and real signatures, with no physical devices."""
import base64
import json
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.hid import CTAPHID

if os.environ.get("SHOUGT_UI_TEST") != "1":
    raise SystemExit("This fixture requires SHOUGT_UI_TEST=1")
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"shougt-sa"))
from backend.fido_bridge import FidoBridge,credential
from backend.piv_bridge import BridgeServer
from tests.test_fido_bridge import SoftwareCtap

fixture=json.loads((Path(os.environ["SHOUGT_UI_WORK"])/"fixture.json").read_text("utf-8"))
stored=fixture["contact_card"]
class FixtureCtap(SoftwareCtap):
    def __init__(self):
        super().__init__()
        self.key=serialization.load_der_private_key(base64.b64decode(stored["private_key"]),None)
        self.credential_id=base64.b64decode(stored["credential_id"])
        self.counter=stored["sign_count"]
        self.user={"id":str(stored["user_id"]).encode(),"name":stored["username"],"displayName":stored["real_name"]}
        self.keys={self.credential_id:(self.key,self.user,self.counter)}
    def call(self,cmd,data=b"",event=None,on_keepalive=None):
        if cmd==CTAPHID.CBOR and len(data)>1:
            body=cbor.decode(data[1:])
            if data[0]==1:
                self.key=ec.generate_private_key(ec.SECP256R1());self.credential_id=os.urandom(32);self.counter=0
            if data[0]==2:
                selected=next((item["id"] for item in body.get(3,[]) if item["id"] in self.keys),self.credential_id)
                self.credential_id=selected;self.key,self.user,self.counter=self.keys[selected]
        response=super().call(cmd,data,event,on_keepalive)
        if cmd==CTAPHID.CBOR and data[0] in {1,2}:self.keys[self.credential_id]=(self.key,self.user,self.counter)
        return response
device=FixtureCtap()
bridge=FidoBridge("http://localhost:15173",allow_loopback_http=True,
    executor=lambda operation,options,reader,origin:credential(operation,options,reader,origin,device_factory=lambda _:device),
    inventory=lambda:[{"id":"fixture-contact","name":"Contact FIDO2Applet (fixture)","transport":"contact","state":"fido_only","piv":False,"fido2":True}])
bridge.pair_code=fixture["fido_pair_code"]
with BridgeServer(18445,bridge) as server:server.serve_forever()
